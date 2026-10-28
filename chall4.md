# WRITE UP: Chall 4 CSCV

## Thu thập thông tin:

### Thông tin được đề cho

Giải nén và đọc các file `.md` có trong bài:

- `README.md` là file đưa ra thông tin đề bài và 2 gợi ý cách làm bài này
- `SHA256SUMS` và `MANIFEST.md` là file đưa ra để kiểm tra lại các file có trong đề bài xem khi được gửi đi có bị hỏng hay không
- `FORMAT.md` là file đưa ra và giải thích các kiểu định dạng như là `.bpf` và `.btf`

Dựa vào file `README.md`, ta có được các thông tin sau:

- Các file được cung cấp là `loader`, `programs.bpf`, `vmlinux.btf`, `bpftool.json`, `ringbuf.dump`, `dns.pcapng`, `flag.enc`, `verify.py`, `FORMAT.md`
- Có 2 gợi ý là không nên dịch riêng lẻ từng file mà nên vẽ đồ thị xuyên chuỗi để làm và có cái DNS bị mất nhưng có thể khôi phục được
- Và để lấy được flag thì chạy `verify.py --proof proof.json --payload recovered.bin`

Trong file `FORMAT.md` thì cho ta biết được các thông tin để giải bài này

- file `proof.json` chứa các trường attach_points, prog_chain, map_ids, uid, parent_hash, session_bit
- `recovered.bin` sẽ lấy được dựa vào việc khôi phục các file bị dấu trong DNS 
- file `program.bpf`là 1 file elf được viết bằng c và được dịch ra bằng clang
- Selector tuple sẽ được lấy từ việc sử dụng `realelf -s` và `readelf -x` để có thể đọc được `.rodata` trong `program.bpf`
- `parent_hash` lưu dạng RAW 8 BYTE -> Đọc xong 8 byte rồi dùng .hex() để ra chuỗi đáp án
- `sel` = struct {u32 uid; u8 session_bit}.
- file `loader` in ra bái boot-ip
- map-ids và prog-id lấy từ `bpftool.json`
- Từ file `dns.pcapng` thì ta có thể giải mã ra 8 byte của file `recovered.bin`

### Thông tin tìm hiểu thêm

File `.bpf` là 1 phần dữ liệu thông tin của của hạt nhân kernel.
Trong bài này, file `.bpf` là file chứa thông tin của hạt nhân từ 1 file ELF được chuyển đổi thành qua lệnh `clang`

File `.btf` là phần metadata của file `.bpf` được tách rời ra khỏi file `.bpf`

## Giải thử thách

### Đọc thông tin .rodata trong `programs.bpf`

Sử dụng `readelf -s programs.bpf` để xem `symbol table`

<img width="812" height="386" alt="image" src="https://github.com/user-attachments/assets/50a1083e-19da-45ae-a4b4-854751cdfee7" />

Ta đọc dữ liệu trong `.rodata` qua lệnh `readelf -x programs.bpf`

<img width="685" height="240" alt="image" src="https://github.com/user-attachments/assets/6d5024db-e688-4da2-b6cd-1b51037014b3" />

Ta có được thông tin trong `.rodata`.

Do như trong file `FORMAT.md` có viết thì do clang BTF datasec offset cho global luôn bằng 0 ở object level nên để chắc chắn thứ tự của từng biến trong đoạn hex trên thì ta dùng lệnh `readelf -s programs.bpf | grep -E "sel|parent_hash|attach_points"

<img width="738" height="106" alt="image" src="https://github.com/user-attachments/assets/21b0ea6d-1f2e-411c-b510-d5058408ab97" />

Từ đó ta lấy được giá trị của 3 biến tương ứng :

`sel` = `e9030000 01000000`
