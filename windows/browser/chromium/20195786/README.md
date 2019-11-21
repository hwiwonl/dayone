# Chrome 72.0.3626.119 FileReader Use-After-Free Vulnerability

CVE-2019-5786 Chrome 72.0.3626.119 stable FileReader UaF exploit for Windows 7 x86. 

This exploit uses site-isolation to brute-force the vulnerability. iframe.html is the wrapper script that loads the exploit, contained in the other files, repeatedly into an iframe.

* python의 `SimpleHTTPServer`와 같은 모듈을 활용하여 `iframe.html` on one site and `exploit.html`, `exploit.js` and `wokrer.js` on another. Change line 13 in `iframe.html` to the URL of exploit.html
* Full exploit이 제대로 동작하기 위해선 --no-sandbox 인자를 포함한 상태로 Chrome.exe를 실행시킬 것
* navigate to iframe.html



# Root Cause Analysis

자세한 정보는 [1]을 참고하였다.


## Patch Analysis

Google은 Chrome에 대한 소스를 제공하고 있으며, 문제가 발생하는 소스코드는 `file_reader_loader.cc`이다. Google이 제공하는 취약한 버전과 패치된 버전의 URL은 다음과 같다.

- old one : https://github.com/chromium/chromium/blob/17cc212565230c962c1f5d036bab27fe800909f9/third_party/blink/renderer/core/fileapi/file_reader_loader.cc
- new one : https://github.com/chromium/chromium/blob/75ab588a6055a19d23564ef27532349797ad454d/third_party/blink/renderer/core/fileapi/file_reader_loader.cc


패치된 함수는 `FileReaderLoader::ArrayBufferResult` 함수로서 패치 전/후의 모습은 다음과 같다.

- Old

```C++
DOMArrayBuffer* FileReaderLoader::ArrayBufferResult() {
  DCHECK_EQ(read_type_, kReadAsArrayBuffer);
  if (array_buffer_result_)
    return array_buffer_result_;

  // If the loading is not started or an error occurs, return an empty result.
  if (!raw_data_ || error_code_ != FileErrorCode::kOK)
    return nullptr;

  DOMArrayBuffer* result = DOMArrayBuffer::Create(raw_data_->ToArrayBuffer());
  if (finished_loading_) {
    array_buffer_result_ = result;
    AdjustReportedMemoryUsageToV8(
        -1 * static_cast<int64_t>(raw_data_->ByteLength()));
    raw_data_.reset();
  }
  return result;
}
```

- New

```C++
DOMArrayBuffer* FileReaderLoader::ArrayBufferResult() {
  DCHECK_EQ(read_type_, kReadAsArrayBuffer);
  if (array_buffer_result_)
    return array_buffer_result_;

  // If the loading is not started or an error occurs, return an empty result.
  if (!raw_data_ || error_code_ != FileErrorCode::kOK)
    return nullptr;

  if (!finished_loading_) {
    return DOMArrayBuffer::Create(
        ArrayBuffer::Create(raw_data_->Data(), raw_data_->ByteLength()));
  }

  array_buffer_result_ = DOMArrayBuffer::Create(raw_data_->ToArrayBuffer());
  AdjustReportedMemoryUsageToV8(-1 *
                                static_cast<int64_t>(raw_data_->ByteLength()));
  raw_data_.reset();
  return array_buffer_result_;
}
```

여기서 패치된 `ArrayBufferResult`의 행위는, 다음과 같이 크게 3가지 경우로 나뉜다.

1. result 값이 캐시된 상태라면, 이를 반환한다.
2. result 값이 캐시되지 않았고, 데이터가 로딩을 끝낸 상태라면(finished loading), `DOMArrayBuffer`를 생성하고(`Create`) 이를 반환한다.
3. result 값이 캐시되지 않았고, 데이터가 로딩을 끝내지 못한 상태라면, 임시 `DOMArrayBuffer`를 생성하고, 이를 반환한다.

패치되지 않은 경우와의 주요 차이점은 3번 항목, 즉, **`finished_loading`이 설정되지 않은 경우에** 해당하는데, 두 경우를 비교하면 구체적인 root cause를 분석할 수 있다.


## Root Cause

- Old
```C++
DOMArrayBuffer* result = DOMArrayBuffer::Create(raw_data_->ToArrayBuffer());
```
- New
```C++
return DOMArrayBuffer::Create(ArrayBuffer::Create(raw_data_->Data(), raw_data_->ByteLength()));
```



패치된 버전은 `DOMArrayBuffer`를 생성하는데 2개의 인자를 사용하는데 (1) `ArrayBuffer::Create` 함수의 반환값 (2) `raw_data_->ByteLength()` 함수 로 구성된다.

`ArrayBuffer::Create(const void*, size_t)` 함수의 원형은 다음과 같다.

```C++
scoped_refptr<ArrayBuffer> ArrayBuffer::Create(const void* source,
                                               size_t byte_length) {
  ArrayBufferContents contents(byte_length, 1, ArrayBufferContents::kNotShared,
                               ArrayBufferContents::kDontInitialize);
  if (UNLIKELY(!contents.Data()))
    OOM_CRASH();
  scoped_refptr<ArrayBuffer> buffer = base::AdoptRef(new ArrayBuffer(contents));
  memcpy(buffer->Data(), source, byte_length);
  return buffer;
}
```

위 함수가 수행하는 것은

1. `ArrayBuffer` 생성
2. `scoped_refptr<ArrayBuffer>`에 1에서 생성된 `ArrayBuffer` 저장
3. `memcpy` 함수를 통해 `source`를 `byte_length`만큼 생성된 버퍼에 복사

이라 말할 수 있다. `scoped_refptr`은 Chrome이 reference count를 관리하는 자료형으로서, 특정 오브젝트를 참조하는 다른 오브젝트의 개수를 나타내기 위해 쓰인다[2].






---


# Reference
[1] https://securingtomorrow.mcafee.com/blogs/other-blogs/mcafee-labs/analysis-of-a-chrome-zero-day-cve-2019-5786/

[2] https://www.chromium.org/developers/smart-pointer-guidelines
