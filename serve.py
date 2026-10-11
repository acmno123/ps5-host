import http.server
import re
import socket
import sys
from pathlib import Path

# =========================================================================
# 配置設定
# =========================================================================
PORT = 8000
ROOT = Path(__file__).resolve().parent

class PS5ExploitHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        # 初始化並指定網頁根目錄
        super().__init__(*args, directory=ROOT, **kwargs)

    def log_message(self, format, *args):
        """ 覆寫日誌輸出，讓終端機只顯示關鍵連線資訊，保持介面乾淨 """
        sys.stdout.write(f"[{self.log_date_time_string()}] 來自 PS5 的請求: {format % args}\n")

    def end_headers(self):
        """ 
        核心優化：注入專為漏洞投放設計的 HTTP 標頭
        """
        # 1. 強制瀏覽器完全不快取（極度重要：防止 PS5 快取錯誤的記憶體指針，造成連續死機）
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        
        # 2. 允許跨來源請求（CORS），方便 WebKit 載入外部 Payload 二進位檔案
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        
        # 3. 提升多執行緒 Web 漏洞穩定性的現代安全標頭
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
        
        super().end_headers()

def get_best_local_ip():
    """ 
    更強的 IP 獲取機制：
    不再依賴外部命令（如 ipconfig）和死板的網段檢查，
    改用 Socket 建立無外部連線，自動獲取目前電腦在區域網路（LAN）中的真實 IP。
    支援 Windows, macOS, Linux 以及 192.168.x.x / 10.x.x.x / 172.x.x.x 所有網段。
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # 使用一個不需要真正建立連線的外部 IP（此處使用 Cloudflare DNS）
        s.connect(('1.1.1.1', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

if __name__ == "__main__":
    # 使用 ThreadingHTTPServer 支援多執行緒併發連線，防止 PS5 非同步請求時伺服器卡死
    with http.server.ThreadingHTTPServer(("0.0.0.0", PORT), PS5ExploitHandler) as server:
        local_ip = get_best_local_ip()
        
        print("=" * 60)
        print("         PS5 高階漏洞投放伺服器 (加強版) 已啟動")
        print("=" * 60)
        print(f"請在 PS5 瀏覽器（使用者指南）中輸入以下網址：")
        print(f"--> http://{local_ip}:{PORT}/")
        print("-" * 60)
        print("等待 PS5 連線中並觸發 WebKit 記憶體鏈...")
        
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n伺服器已安全關閉。")
