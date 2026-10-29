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

- file `proof.json` chứa các trường `attach_points`, `prog_chain`, `map_ids`, `uid`, `parent_hash`, `session_bit`
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

## File `proof.json`

### Tìm  các trường `attach_points`, `uid`,`parent_hash`, `session_bit`

Sử dụng `readelf -s programs.bpf` để xem `symbol table`

<img width="812" height="386" alt="image" src="https://github.com/user-attachments/assets/50a1083e-19da-45ae-a4b4-854751cdfee7" />

Ta đọc dữ liệu trong `.rodata` qua lệnh `readelf -x programs.bpf`

<img width="685" height="240" alt="image" src="https://github.com/user-attachments/assets/6d5024db-e688-4da2-b6cd-1b51037014b3" />

Ta có được thông tin trong `.rodata`.

Do như trong file `FORMAT.md` có viết thì do clang BTF datasec offset cho global luôn bằng 0 ở object level nên để chắc chắn thứ tự của từng biến trong đoạn hex trên thì ta dùng lệnh `readelf -s programs.bpf | grep -E "sel|parent_hash|attach_points"`

<img width="738" height="106" alt="image" src="https://github.com/user-attachments/assets/21b0ea6d-1f2e-411c-b510-d5058408ab97" />

Từ đó ta lấy được giá trị của 3 biến tương ứng :

`sel` = `e9030000 01000000`

`parent_hash` = `ab77fe24 675b6427`(16 hex đáp)

`attach_points` = `74726163 65706f69 6e742f70 726f6365 73732d65 78656300 686f6f6b 2f736f63`

Mà từ file `FORMAT.md` ta biết `sel` = struct {u32 uid; u8 session_bit}.

Nên `uid` = `0x03e9` và `session_bit` = `0x01`

### Tìm các trường `prog_chain`, `map_ids`

mởi file `bpftool.json`:

```


  "programs": [
    {
      "id": 41,
      "map_ids": [
        7
      ],
      "tail_call": 42
    },
    {
      "id": 42,
      "map_ids": [
        7
      ],
      "tail_call": null
    }
  ],
  "maps": [
    {
      "id": 7,
      "name": "map_7"
    }
  ]
}

```

Ta thấy trong file đấy có 2 `prog_id` lần lượt là 41 và 42 nên trường `prog_chain : [41,42]`

Đồng thời `map_ids : [7]`

### Tạo file `proof.json` 

File `proof.json`:

```

{
    "attach_points" : ["tracepoint/process-exec", "hook/soc"] , "prog_chain" : [41,42], "map_ids" : [7], "uid": 0x03e9, "parent_hash" : "ab77fe24675b6427", session_bit : 1
}

```

### File `recovered.bin`

Mở file `dns.pcapng`:

<img width="707" height="90" alt="image" src="https://github.com/user-attachments/assets/a08f63ae-a571-426e-908c-f4d5724b602c" />

Đoạn code giải mã base32 và tìm ra f1:

```

import base64

b32_f0 = "DMMOG4EMDTGT2"
b32_f2 = "FBK3RWPYSKZV2"
b32_f3 = "W6KVUGZAOX43I"
b32_parity = "R5PVZKUMKM5AC"


def b32_decode(s):
  # Bù dấu '=' cho đủ độ dài chia hết cho 8 của chuẩn Base32
  pad_len = (8 - len(s) % 8) % 8
  return base64.b32decode(s + "=" * pad_len)

f0 = b32_decode(b32_f0)
f2 = b32_decode(b32_f2)
f3 = b32_decode(b32_f3)
parity = b32_decode(b32_parity)
f1 = bytes(a ^ b ^ c ^ d for a, b, c, d in zip(f0, f2, f3, parity))
print("f1 (Hex)       :", f1.hex())

```

Do len của tin truyền đi là 32 byte mà mỗi thông tin gửi đi có 8 byte, nên thông tin gửi đi hoàn chỉnh là `1b18e3710c1e669a1187476716ac94702855b8d9f892b35ab7955a1b2075f9b2`

Đoạn mã tìm steamkey:

```

import hashlib
import json

meta = {"uid": 1001, "session_bit": 1, "parent_hash": "ab77fe24675b6427"}
boot_id = "28f227e7-123e-e84f-c023-fc215e94e7d2"

canonical_json = json.dumps(meta, separators=(",", ":"), sort_keys=True)

seed_string = canonical_json + boot_id

stream_key = hashlib.sha256(seed_string.encode("utf-8")).digest()

print("streamkey (Hex):", stream_key.hex())

```

streamkey = `d9ef473943eced20a91f8fa700c5cdbef96be6fa6b0e51678d7f6faca2c3ae61`

Đoạn mã tìm keystream:

```

import hashlib

stream_key_hex = (
    "9a64bf7727e4eec47d2f33f990a071569a918a53e9a11a88be3381a17937d570"
)
stream_key = bytes.fromhex(stream_key_hex)

i = 0
block_index = i.to_bytes(4, byteorder="big")

data_to_hash = stream_key + block_index

keystream = hashlib.sha256(data_to_hash).digest()

print("Keystream (Hex)  :", keystream.hex())

```

keystream = `9be1c0189a10caeadb8733d2d961e4ca43cc7c0b022c72ac36726afab4533771`

Đoạn mã tính `payload` dồng thời cũng xuất ra file `recovered.bin`

## Verify và lấy flag

<img width="662" height="61" alt="image" src="https://github.com/user-attachments/assets/dc5d33c6-3824-4a2d-80c0-7ad2b0fb5ad7" />

Vậy flag là `CSCV2026{bpf_t4il_c4lls_l34v3_aud1t4bl3_tr4c3s}`
