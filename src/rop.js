"use strict";

// 假設全域 int64 類別已存在，建立安全的轉型檢查
function isInt64(obj) {
    return obj && typeof obj === 'object' && 'low' in obj && 'hi' in obj;
}

class rop {
    constructor(p, stack_size = 0x80000, reserved_stack = 0x10000) {
        this.stack_size = stack_size;
        this.reserved_stack = reserved_stack;
        this.stack_dwords = stack_size / 4;
        this.reserved_stack_index = reserved_stack / 4;

        // 分配 ROP 棧記憶體空間
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

    clear() {
        this.count = 0;
        this.stack_array.set(this.zeroed_stack);
    }

    // 1. 強度優化：移除所有破壞時序的 alert() 彈窗，改用高階日誌引擎攔截
    push(value) {
        const index = this.reserved_stack_index + this.count++ * 2;
        
        if (isInt64(value)) {
            this.stack_array[index] = value.low;
            this.stack_array[index + 1] = value.hi;
        } else if (typeof value === "number") {
            if (value > 0xffffffff) {
                if (window.log_to_ps5) {
                    window.log_to_ps5("[-] ROP 嚴格防護警告：試圖寫入超越 32-bit 的數值，請使用 int64 實例！", "err");
                }
            }
            this.stack_array[index] = value;
            this.stack_array[index + 1] = 0;
        } else {
            if (window.log_to_ps5) {
                window.log_to_ps5("[-] ROP 嚴格防護錯誤：試圖寫入非數值/非 int64 欄位！", "err");
            }
        }
    }

    // 安全核心：確保壓入的 Gadget 位址合法，防止盲跳死機
    push_gadget(name) {
        const g = this.gadgets[name];
        if (g === undefined || g === null || g === 0) {
            if (window.log_to_ps5) window.log_to_ps5(`[-] 關鍵錯誤：找不到必備組件 Gadget -> [${name}]`, "err");
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

    push_sysv(rdi, rsi, rdx, rcx, r8, r9) {
        const args = [rdi, rsi, rdx, rcx, r8, r9];
        const regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
        for (let i = 0; i < args.length; i++) {
            if (args[i] === undefined) continue;
            this.push_gadget("pop " + regs[i]);
            this.push(args[i]);
        }
    }

    // 2. 核心加強點：硬性 x86-64 棧 16 位元組對齊（16-byte Stack Alignment Guard）
    // 現代 CPU 執行諸如 SSE/AVX 核心指令時，若 RSP 未對齊 16 級距，會直接引發 General Protection Fault (#GP) 死機
    fcall(rip, rdi, rsi, rdx, rcx, r8, r9) {
        this.push_sysv(rdi, rsi, rdx, rcx, r8, r9);
        
        // 動態推算當前的虛擬棧記憶體指標位置是否符合 16 位元組邊界
        const current_rsp_low = this.stack_entry_point.add32(this.count * 8).low;
        if (current_rsp_low & 8) {
            this.push_gadget("ret"); // 填補一個安全的 ret 小工具以強迫對齊 16-byte
        }
        
        if (rip === undefined || rip === null || rip === 0) {
            throw new Error("Invalid target function pointer (RIP is null)");
        }
        this.push(rip);
    }

    add_syscall(sysc, rdi, rsi, rdx, rcx, r8, r9) {
        const sys_addr = this.syscalls[sysc];
        if (!sys_addr) {
            if (window.log_to_ps5) window.log_to_ps5(`[-] 錯誤：當前韌體不支援系統呼叫編號 -> [0x${sysc.toString(16)}]`, "err");
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

    clear() {
        super.clear();
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

    // 3. 強度優化：非同步管道流程控管
    async run() {
        try {
            await this.p.launch_chain(this);
        } catch (chainError) {
            if (window.log_to_ps5) {
                window.log_to_ps5(`[-] ROP 執行緒調度失敗: ${chainError.message}`, "err");
            }
            throw chainError;
        } finally {
            this.clear(); // 無論成功與否，強迫擦除偽造棧記憶體，防止指標殘留
        }
    }
}

// 導出模組
window.rop = rop;
window.worker_rop = worker_rop;
