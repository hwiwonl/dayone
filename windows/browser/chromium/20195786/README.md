# Chrome 72.0.3626.119 FileReader Use-After-Free Vulnerability

CVE-2019-5786 Chrome 72.0.3626.119 stable FileReader UaF exploit for Windows 7 x86. 

This exploit uses site-isolation to brute-force the vulnerability. iframe.html is the wrapper script that loads the exploit, contained in the other files, repeatedly into an iframe.

* python의 `SimpleHTTPServer`와 같은 모듈을 활용하여 `iframe.html` on one site and `exploit.html`, `exploit.js` and `wokrer.js` on another. Change line 13 in `iframe.html` to the URL of exploit.html
* Full exploit이 제대로 동작하기 위해선 `--no-sandbox` 인자를 commandline에 포함한 상태로 Chrome.exe를 실행시킬 것
* Chrome으로 `iframe.html`을 방문하게 되면 exploit이 수행된다.





## Root Cause Analysis

자세한 정보는 [1], [8]을 참고하였다.

The FileReader object lets web applications asynchronously read the contents of files (or raw data buffers) stored on the user's computer, using File or Blob objects to specify the file or data to read.


### Patch Analysis

Google은 Chrome에 대한 소스를 제공하고 있으며, 문제가 발생하는 소스코드는 `file_reader_loader.cc`이다. Google이 제공하는 취약한 버전과 패치된 버전의 URL은 다음과 같다.

- old one : https://github.com/chromium/chromium/blob/17cc212565230c962c1f5d036bab27fe800909f9/third_party/blink/renderer/core/fileapi/file_reader_loader.cc
- new one : https://github.com/chromium/chromium/blob/75ab588a6055a19d23564ef27532349797ad454d/third_party/blink/renderer/core/fileapi/file_reader_loader.cc


패치된 함수는 `FileReaderLoader::ArrayBufferResult` 함수로서 패치 전/후의 모습은 다음과 같다.

- Old `FileReaderLoader::ArrayBufferResult`

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

- New `FileReaderLoader::ArrayBufferResult`

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


##### Old
```C++
DOMArrayBuffer* result = DOMArrayBuffer::Create(raw_data_->ToArrayBuffer());
```
##### New
```C++
return DOMArrayBuffer::Create(ArrayBuffer::Create(raw_data_->Data(), raw_data_->ByteLength()));
```


위 비교에서 확인할 수 있듯, 두 가지 버전의 주요 차이점은 `DOMArrayBuffer::Create`에 사용되는 인자가 서로 다르다.

패치 전의 인자는 `ArrayBufferBuilder::ToArrayBuffer()`를 사용하고 있으며, 패치 후의 경우,  `ArrayBuffer::Create` 함수로 변경되었다. 두 경우 모두 `scoped_refptr<ArrayBuffer>` 형태의 값을 반환한다.

먼저 패치된 버전을 살펴보면 `ArrayBuffer::Create` 함수는 2개의 인자를 사용하는데 (1) `Data` (2) `ByteLength`로 구성된다.
`ArrayBuffer::Create(const void*, size_t)` 함수의 원형은 다음과 같다.

##### `ArrayBuffer::Create(const void*, size_t)`
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

이라 말할 수 있다. 2에서 사용되는 `scoped_refptr`은 Chrome이 reference count를 관리하는 자료형으로서, 특정 오브젝트를 참조하는 다른 오브젝트의 개수를 나타내기 위해 쓰인다[2]. 이는 Use-After-Free 버그와 특히 관계가 깊은 부분으로서,



반대로 패치 전의 코드에서 사용하는 `ArrayBufferBuilder::ToArrayBuffer()` 함수를 살펴보면 다음과 같다. [3]

##### `ArrayBufferBuilder::ToArrayBuffer()`

```C++
scoped_refptr<ArrayBuffer> ArrayBufferBuilder::ToArrayBuffer() {
  // Fully used. Return m_buffer as-is.
  if (buffer_->ByteLength() == bytes_used_)
    return buffer_;

  return buffer_->Slice(0, bytes_used_);
}
```
`ToArrayBuffer` 함수는 크게 2가지의 경우로 나뉘는데, 하나는 `buffer_->ByteLength() == bytes_used_`를 만족하는 경우로 `ArrayBufferBuilder`의 멤버 변수인 `buffer_` 값을 **아무런 조작없이 그대로 반환**한다(`buffer_`의 선언은 [4]에 나타나있다). 그 반대의 경우, 현재 `ArrayBufferBuilder`의 `bytes_used_` 개수만큼의 데이터를 다음과 같이 복사하게 된다.

그 반대의 경우, `ArrayBuffer::Slice(int begin, int end)` 함수를 실행시키게 된다. [5][6]

##### `ArrayBuffer::Slice(int begin, int end)`
```C++
scoped_refptr<ArrayBuffer> ArrayBuffer::Slice(int begin, int end) const {
  return SliceImpl(ClampIndex(begin), ClampIndex(end));
}

scoped_refptr<ArrayBuffer> ArrayBuffer::SliceImpl(unsigned begin,
                                                  unsigned end) const {
  size_t size = static_cast<size_t>(begin <= end ? end - begin : 0);
  return ArrayBuffer::Create(static_cast<const char*>(Data()) + begin, size);
}
```

`Slice` 함수는 `SliceImpl`를 호출하고, 이어서 `SliceImpl`는 `ArrayBuffer::Create`를 통해 **새로운 `ArrayBuffer`를 생성**하고 이를 반환한다.


즉, 취약한 버전과 패치된 버전의 주요 차이점은

- `finished_loading_`이 set되지 않은 상태에서(로드가 완료되지 않은 상태에서)
- `buffer_->ByteLength() == bytes_used_`를 만족하는 경우,
- `DOMArrayBuffer::Create`의 인자로 새로 생성되지 않은 기존의 `scoped_refptr<ArrayBuffer>`가 전달된다

으로 정리할 수 있다.




### Root Cause Analysis

#### Creating Dangling Pointer

`FileReaderLoader::ArrayBufferResult`가 실행하는 `DOMArrayBuffer::Create`는 다음과 같다.

##### `DOMArrayBuffer::Create`
```C++
  static DOMArrayBuffer* Create(scoped_refptr<WTF::ArrayBuffer> buffer) {
    return MakeGarbageCollected<DOMArrayBuffer>(std::move(buffer));
  }
```

`DOMArrayBuffer::Create` 함수는 인자로 전달된 버퍼를 `std::move` 함수를 통해 `DOMArrayBuffer` 클래스로 이동시킨다.
C++의 `std::move`는 오브젝트를 이동시키기 위한 함수로서, 일반적인 copy와는 그 동작이 다르다 예를 들어,

```C++
  template <class T>
  swap1(T& a, T& b) {
      T tmp(a);   // a의 copy 생성.
      a = b;      // b의 copy 생성 (+ a의 copy 중 하나 소멸)
      b = tmp;    // tmp의 copy가 2개가 됨 (+b의 copy 중 하나 소멸)
  }

  //move를 쓰면 copy하지 않고 swap이 가능해 짐
  template <class T>
  swap2(T& a, T& b) {
      T tmp(std::move(a));
      a = std::move(b);   
      b = std::move(tmp);
  }
```
위와 같은 코드가 주어졌을 때, `swap1`의 경우, 여러번의 copy가 발생하지만, `swap2`의 경우, copy 없이도 오브젝트 간의 이동을 통해 swap 기능을 구현하였다. 여기서 중요한 점은 `std::move`를 통해 오브젝트를 이동시키면 기존에 오브젝트를 가지고 있던 변수는 undefined 상태가 된다는 점이다. 예를 들어,

```C++
  string a = "hello";
  string b = std::move(a);
```
위 코드에서 `a`에는 더이상 `"hello"`가 남아있지 않게 된다.




### Triggering Free



##### SerializedScriptValue::ArrayBufferContentsArray [8]

```C++
SerializedScriptValue::ArrayBufferContentsArray
SerializedScriptValue::TransferArrayBufferContents(
    v8::Isolate* isolate,
    const ArrayBufferArray& array_buffers,
    ExceptionState& exception_state) {
  ArrayBufferContentsArray contents;

  if (!array_buffers.size())
    return ArrayBufferContentsArray();

  for (auto* it = array_buffers.begin(); it != array_buffers.end(); ++it) {
    DOMArrayBufferBase* array_buffer = *it;
    if (array_buffer->IsNeutered()) {
      wtf_size_t index =
          static_cast<wtf_size_t>(std::distance(array_buffers.begin(), it));
      exception_state.ThrowDOMException(DOMExceptionCode::kDataCloneError,
                                        "ArrayBuffer at index " +
                                            String::Number(index) +
                                            " is already neutered.");
      return ArrayBufferContentsArray();
    }
  }

  contents.Grow(array_buffers.size());
  HeapHashSet<Member<DOMArrayBufferBase>> visited;
  for (auto* it = array_buffers.begin(); it != array_buffers.end(); ++it) {
    DOMArrayBufferBase* array_buffer_base = *it;
    if (visited.Contains(array_buffer_base))
      continue;
    visited.insert(array_buffer_base);

    wtf_size_t index =
        static_cast<wtf_size_t>(std::distance(array_buffers.begin(), it));
    if (array_buffer_base->IsShared()) {
      exception_state.ThrowDOMException(DOMExceptionCode::kDataCloneError,
                                        "SharedArrayBuffer at index " +
                                            String::Number(index) +
                                            " is not transferable.");
      return ArrayBufferContentsArray();
    } else {
      DOMArrayBuffer* array_buffer =
          static_cast<DOMArrayBuffer*>(array_buffer_base);

      if (!array_buffer->Transfer(isolate, contents.at(index))) {
        exception_state.ThrowDOMException(DOMExceptionCode::kDataCloneError,
                                          "ArrayBuffer at index " +
                                              String::Number(index) +
                                              " could not be transferred.");
        return ArrayBufferContentsArray();
      }
    }
  }
  return contents;
}
```



---


## References

[1] https://securingtomorrow.mcafee.com/blogs/other-blogs/mcafee-labs/analysis-of-a-chrome-zero-day-cve-2019-5786/

[2] https://www.chromium.org/developers/smart-pointer-guidelines

[3] https://github.com/chromium/chromium/blob/17cc212565230c962c1f5d036bab27fe800909f9/third_party/blink/renderer/platform/wtf/typed_arrays/array_buffer_builder.cc#L103

[4] https://github.com/chromium/chromium/blob/17cc212565230c962c1f5d036bab27fe800909f9/third_party/blink/renderer/platform/wtf/typed_arrays/array_buffer_builder.h#L94

[5] https://github.com/chromium/chromium/blob/17cc212565230c962c1f5d036bab27fe800909f9/third_party/blink/renderer/platform/wtf/typed_arrays/array_buffer.h#L264

[6] https://github.com/chromium/chromium/blob/17cc212565230c962c1f5d036bab27fe800909f9/third_party/blink/renderer/platform/wtf/typed_arrays/array_buffer.h#L272

[7] https://github.com/chromium/chromium/blob/17cc212565230c962c1f5d036bab27fe800909f9/third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h#L20


[8] https://blog.exodusintel.com/2019/03/20/cve-2019-5786-analysis-and-exploitation/

[9] https://github.com/chromium/chromium/blob/17cc212565230c962c1f5d036bab27fe800909f9/third_party/blink/renderer/bindings/core/v8/serialization/serialized_script_value.cc#L683

[10] why-are-transfered-buffers-neutered-in-javascript : https://stackoverflow.com/questions/38169672/why-are-transfered-buffers-neutered-in-javascript



