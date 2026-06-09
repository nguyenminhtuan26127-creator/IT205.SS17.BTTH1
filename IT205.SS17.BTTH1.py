"""
Security Log Analyzer
- Clean logs using translate + maketrans
- Filter ERROR/CRITICAL logs
- Mask IP addresses
- Uses match-case instead of main()
"""

# GLOBAL VARIABLES
raw_logs = []
processed_logs = []

# CLEANING FUNCTIONS
def create_cleaning_table():
    """
    Tạo bảng xóa ký tự đặc biệt
    """
    return str.maketrans("", "", "!@#$")


def split_logs(text: str):
    """
    Tách chuỗi log theo dấu ;
    """
    return text.split(";")


def clean_log(log: str, table):
    """
    Làm sạch 1 log
    """
    return log.translate(table).strip()


def clean_logs(text: str):
    """
    Làm sạch toàn bộ logs
    """
    global raw_logs

    table = create_cleaning_table()
    logs = split_logs(text)

    raw_logs = [clean_log(log, table) for log in logs]
    return raw_logs


# FILTER FUNCTIONS

def is_high_risk(log: str):
    """
    Kiểm tra ERROR/CRITICAL
    """
    log = log.lower()
    return "error" in log or "critical" in log


def filter_logs():
    """
    Lọc log nguy hiểm
    """
    global processed_logs

    if not raw_logs:
        print("Chưa có dữ liệu log, vui lòng thực hiện chức năng 1")
        return []

    processed_logs = [
        log for log in raw_logs
        if is_high_risk(log)
    ]

    return processed_logs


# IP MASKING FUNCTIONS
def is_ip(word: str):
    """
    Kiểm tra IP
    """
    return word.count(".") == 3


def split_ip(ip: str):
    """
    Tách IP
    """
    return ip.split(".")


def mask_ip(parts):
    """
    Che 2 phần cuối IP
    """
    return f"{parts[0]}.{parts[1]}.*.*"


def mask_word(word: str):
    """
    Mask nếu là IP
    """
    if is_ip(word):
        parts = split_ip(word)
        if len(parts) == 4:
            return mask_ip(parts)
    return word


def mask_log(log: str):
    """
    Mask IP trong 1 log
    """
    words = log.split()
    return " ".join([mask_word(w) for w in words])


def mask_logs():
    """
    Mask toàn bộ logs
    """
    if not processed_logs:
        print("Chưa có dữ liệu log, vui lòng thực hiện chức năng 2")
        return []

    return [mask_log(log) for log in processed_logs]


# UTILITY FUNCTIONS
def print_logs(title: str, logs: list):
    """
    In danh sách log
    """
    print(f"\n{title}")
    for i, log in enumerate(logs, 1):
        print(f"{i}. {log}")


while True:
    print("\n============= SECURITY LOG ANALYZER =============")
    print("1. Nhập và làm sạch dữ liệu Log thô")
    print("2. Lọc các Log cảnh báo (ERROR/CRITICAL)")
    print("3. Mã hóa địa chỉ IP (Masking)")
    print("4. Đóng hệ thống")
    print("=================================================")
    choice = input("Chọn chức năng (1-4): ")

    match choice:

        case "1":
            print("\n--- NẠP DỮ LIỆU LOG ---")
            data = input("Nhập chuỗi log thô (cách nhau bởi dấu ;): ")
            logs = clean_logs(data)
            print(f"Đã làm sạch và lưu {len(logs)} dòng log.")

        case "2":
            print("\n--- LỌC CẢNH BÁO ---")
            logs = filter_logs()
            if logs:
                print_logs("Tìm thấy cảnh báo nguy hiểm:", logs)

        case "3":
            print("\n--- MÃ HÓA IP ---")
            logs = mask_logs()
            if logs:
                print_logs("Báo cáo log an toàn:", logs)

        case "4":
            print("Hệ thống đã đóng.")
            break

        case _:
            print("Lựa chọn không hợp lệ!")