"use strict";

// 建立安全且不依賴全域類別名稱的 64位元指標特徵校驗 (Duck Typing)
function isPlausibleInt64(obj) {
    return obj && typeof obj === 'object' && ('low' in obj || 'low16' in obj) && 'hi' in obj;
}

class rop {
    constructor(p, stack_size = 0x80000, reserved_stack = 0x10000) {
        this.stack_size = stack_size;
        this.reserved_stack = reserved_stack;
        this.stack_dwords = stack_size / 4;
        this.reserved_stack_index = reserved_stack / 4;

        // 分配並初始化 ROP 專屬虛擬棧記憶體
        this.stack_memory = p.malloc(this.stack_dwords + 0x2 + 0x200);
        this.stack_array = this.stack_memory.backing;
        this.zeroed_stack = new Uint32Array(this.stack_dwords);
        this.stack_entry_point = this.stack_memory.add32(reserved_stack);
        this.return_value = this.stack_memory.add32(stack_size);

        this.p = p;
        this.gadgets = p.gadgets;
        this.syscalls = p.syscalls;
        this.count = 0;
    }

    // 僅清理記憶體數值，斷開鏈式重複綁定
    clear_stack_data() {
        this.count = 0;
        this.stack_array.set(this.zeroed_stack);
    }

    clear() {
        this.clear_stack_data();
    }

    push(value) {
        const index = this.reserved_stack_index + this.count++ * 2;
        
        if (isPlausibleInt64(value)) {
            this.stack_array[index] = value.low;
            this.stack_array[index + 1] = value.hi;
        } else if (typeof value === "number") {
            if (value > 0xffffffff && window.log_to_ps5) {
                window.log_to_ps5("[-] ROP 邊界警告：數值超越 32位元 限制，請轉換為 int64 指標！", "warn");
            }
            this.stack_array[index] = value;
            this.stack_array[index + 1] = 0;
        } else {
            if (window.log_to_ps5) {
                window.log_to_ps5("[-] ROP 嚴格攔截：拒絕寫入非標準記憶體類型物件！", "err");
            }
        }
    }

    // 安全防護點：硬性檢查 Gadget 有效性，防止 RIP 跳轉至無效位址（0x0）
    push_gadget(name) {
        const g = this.gadgets[name];
        if (g === undefined || g === null || g === 0) {
            if (window.log_to_ps5) window.log_to_ps5(`[-] 關鍵衝突：目標指令小工具不存在 -> [${name}]`, "err");
            throw new Error(`Required gadget missing: ${name}`);
        }
        this.push(g);
    }

    push_write8(dest, value) {
        this.push_gadget("pop rdi");
        this.push(dest);
        this.push_gadget("pop rsi");
        this.push(value);
        this.push_gadget("mov [rdi], rsi");
    }

    write_result(dest) {
        this.push_gadget("pop rdi");
        this.push(dest);
        this.push_gadget("mov [rdi], rax");
    }

    // 加強點：採用靜態分支解耦，徹底取代原版字串拼接，提升 CPU System V ABI 暫存器傳參效率
    push_sysv(rdi, rsi, rdx, rcx, r8, r9) {
        if (rdi !== undefined) { this.push_gadget("pop rdi"); this.push(rdi); }
        if (rsi !== undefined) { this.push_gadget("pop rsi"); this.push(rsi); }
        if (rdx !== undefined) { this.push_gadget("pop rdx"); this.push(rdx); }
        if (rcx !== undefined) { this.push_gadget("pop rcx"); this.push(rcx); }
        if (r8 !== undefined)  { this.push_gadget("pop r8");  this.push(r8);  }
        if (r9 !== undefined)  { this.push_gadget("pop r9");  this.push(r9);  }
    }

    // 16 位元組虛擬棧邊界強制對齊
    fcall(rip, rdi, rsi, rdx, rcx, r8, r9) {
        this.push_sysv(rdi, rsi, rdx, rcx, r8, r9);
        
        // 實時推算 RSP 暫存器低位，若未對齊則插入安全滑行指令（ret墊片），防止觸發硬體 #GP 異常
        const current_rsp_low = this.stack_entry_point.add32(this.count * 8).low;
        if ((current_rsp_low & 8) !== 0) {
            this.push_gadget("ret"); 
        }
        
        if (rip === undefined || rip === null || rip === 0) {
            throw new Error("Invalid target instruction pointer (RIP is dead)");
        }
        this.push(rip);
    }

    add_syscall(sysc, rdi, rsi, rdx, rcx, r8, r9) {
        const sys_addr = this.syscalls[sysc];
        if (!sys_addr) {
            if (window.log_to_ps5) window.log_to_ps5(`[-] 系統錯誤：當前環境未開放此呼叫號 -> [0x${sysc.toString(16)}]`, "err");
            throw new Error(`Syscall not found: 0x${sysc.toString(16)}`);
        }
        this.fcall(sys_addr, rdi, rsi, rdx, rcx, r8, r9);
    }
}

class worker_rop extends rop {
    constructor(p, stack_size, reserved_stack) {
        super(p, stack_size, reserved_stack);
        this.p.pre_chain(this);
    }

    // 覆寫清理函式，確保只有在正確的排程週期才進行鏈結前置綁定
    clear() {
        this.clear_stack_data();
        this.p.pre_chain(this);
    }

    async call(rip, rdi, rsi, rdx, rcx, r8, r9) {
        this.fcall(rip, rdi, rsi, rdx, rcx, r8, r9);
        this.write_result(this.return_value);
        await this.run();
        return this.p.read8(this.return_value);
    }

    async syscall(sysc, rdi, rsi, rdx, rcx, r8, r9) {
        return await this.call(this.syscalls[sysc], rdi, rsi, rdx, rcx, r8, r9);
    }

    add_syscall_ret(retstore, sysc, rdi, rsi, rdx, rcx, r8, r9) {
        const sys_addr = this.syscalls[sysc];
        if (!sys_addr) {
            throw new Error(`Syscall not found for ret: 0x${sysc.toString(16)}`);
        }
        this.fcall(sys_addr, rdi, rsi, rdx, rcx, r8, r9);
        this.write_result(retstore);
    }

    // 非同步管道阻塞優化
    async run() {
        try {
            await this.p.launch_chain(this);
        } catch (chainError) {
            if (window.log_to_ps5) {
                window.log_to_ps5(`[-] ROP 執行緒硬體同步失敗: ${chainError.message}`, "err");
            }
            throw chainError;
        } finally {
            // 安全隔離：在退出當前工作線程時，強制抹除整個棧陣列，但延遲 pre_chain 綁定，避免內存競態混淆
            this.clear_stack_data();
        }
    }
}

// 掛載至全域全域空間
window.rop = rop;
window.worker_rop = worker_rop;
