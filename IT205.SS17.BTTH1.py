'''
PHÂN TÍCH & THIẾT KẾ HỆ THỐNG

1. MỤC TIÊU HỆ THỐNG
- Làm sạch dữ liệu log chứa ký tự rác.
- Tách nhiều log từ chuỗi nhập bằng split().
- Lọc log nguy hiểm chứa ERROR hoặc CRITICAL.
- Mã hóa địa chỉ IP để bảo mật thông tin.
- Tối ưu xử lý chuỗi bằng:
    + str.translate()
    + str.maketrans()
    + split()
    + join()
    + List Comprehension

2. PHÂN TÍCH maketrans() VÀ translate()
- str.maketrans("", "", "!@#$")
  tạo bảng ánh xạ để xóa các ký tự đặc biệt.

- Ví dụ:
    ! -> xóa
    @ -> xóa
    # -> xóa
    $ -> xóa

- translate() duyệt chuỗi 1 lần duy nhất và áp dụng
  bảng mapping để xử lý nhanh hơn dùng nhiều replace().

- Ví dụ:
    Input:
        ERR!OR 192.168.1.1 Failed@ login

    Output:
        ERROR 192.168.1.1 Failed login

3. LUỒNG XỬ LÝ CHỨC NĂNG 1
- Người dùng nhập chuỗi log.
- split(";") để tách nhiều log.
- translate(table) để xóa ký tự rác.
- strip() để loại bỏ khoảng trắng dư.
- Lưu kết quả vào raw_logs.

4. LUỒNG XỬ LÝ CHỨC NĂNG 2
- Kiểm tra raw_logs có dữ liệu hay không.
- Dùng List Comprehension để lọc log chứa:
    + ERROR
    + CRITICAL

- Code:
    processed_logs = [
        log for log in raw_logs
        if is_high_risk(log)
    ]

- Kết quả lưu vào processed_logs.

5. LUỒNG XỬ LÝ CHỨC NĂNG 3
- Duyệt từng log nguy hiểm.
- split() để tách từng từ.
- Kiểm tra IP bằng count(".") == 3.
- split(".") để tách IP thành 4 phần.
- Mask 2 cụm cuối:
    192.168.1.1
    ->
    192.168.*.*

- join() để ghép chuỗi lại.

6. THIẾT KẾ HÀM
- Mỗi hàm chỉ thực hiện 1 nhiệm vụ.
- Tăng khả năng tái sử dụng.
- Dễ bảo trì và kiểm thử.

7. EDGE CASES
- Nếu chưa có dữ liệu:
    + Chức năng 2:
        "Chưa có dữ liệu log, vui lòng thực hiện chức năng 1"

    + Chức năng 3:
        "Chưa có dữ liệu log, vui lòng thực hiện chức năng 2"

- Nếu log không chứa IP:
    + Giữ nguyên log.
    + Không làm chương trình lỗi.

8. KỸ THUẬT ĐÃ SỬ DỤNG
- split()
- join()
- translate()
- maketrans()
- List Comprehension
- match-case
- Docstring
- snake_case
'''



# Security Log Analyzer

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
