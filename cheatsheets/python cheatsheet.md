# FOUNDATION

## List

* list.append(element)
* list.insert(position, element)
* list1.extend(list2)
* sum(list)
* list.count(element)
* len(list)
* list.index(element, start*, end*)
* min(list)
* max(list)
* list.sort(reverse=False)
* list.pop(index)
* list.remove(element) - removes only one occurance

***

## String

* string.lower()
* string.upper()
* string.isalnum()
* string.isalpha()
* string.isnumeric()
* string.islower()
* string.isupper()
* string.isspace()
* string.istitle()
* len(string)
* string1.join(string2/list) - opposite of split
* string.split()
* string.replace()
* string.count(substring)

***

## Stack

**import queue**

**stack = queue.LifoQueue(maxsize = size)**

* stack.qsize()
* stack.put(element)
* stack.get()
* stack.full()
* stack.empty()

***

## Queue

**import queue**

**q = queue.Queue(maxsize=size)**

* q.put(element)
* q.get()
* q.full()
* q.empty()

***

## Euclid's GCD

>def gcd(a, b):  
>>if a == 0 : 
>>>return b  
>>     
>>return gcd(b%a, a)

***

## Binary Search

* bisect(list, num, beg, end) - returns rightmost postition where the num has to be inserted.
* bisect_left(list, num, beg, end) - returns leftmost position where the num has to be inserted.
* bisect_right(list, num, beg, end) - returns rightmost position where the num has to be inserted.
* insort(list, num, beg, end) - returns sorted list after inserting num to rightmost postion.
* insort_left(list, num, beg, end) - returns sorted list after inserting num to leftmost postion.
* insort_right(list, num, beg, end) - returns sorted list after inserting num to rightmost postion.

## Priority Queue

**import heapq**

* heapify(iterable) :- This function is used to convert the iterable into a heap data structure. i.e. in heap order.
* heappush(heap, ele) :- This function is used to insert the element mentioned in its arguments into heap. The order is adjusted, so as heap structure is maintained.
* heappop(heap) :- This function is used to remove and return the smallest element from heap. The order is adjusted, so as heap structure is maintained.
* heappushpop(heap, ele) :- This function combines the functioning of both push and pop operations in one statement, increasing efficiency. Heap order is maintained after this operation.
* heapreplace(heap, ele) :- This function also inserts and pops element in one statement, but it is different from above function. In this, element is first popped, then element is pushed.i.e, the value larger than the pushed value can be returned.
* nlargest(k, iterable, key = fun) :- This function is used to return the k largest elements from the iterable specified and satisfying the key if mentioned.
* nsmallest(k, iterable, key = fun) :- This function is used to return the k smallest elements from the iterable specified and satisfying the key if mentioned.

***

## Disjoint Sets

>def MAKE_SET(x):
>>return [x]

>sets = [MAKE_SET(v) for v in elements]

>set_member_lookup = {}
>>for index, v in enumerate(vertices):
>>>set_member_lookup[v] = index

>def FIND_SET(x):
>>return set_member_lookup[x]

>def UNION(set_u, set_v):
>>if sets[set_u] is not None:
>>>if sets[set_v] is not None:
>>>>sets[set_u].extend(sets[set_v])
>>>>
>>>>for k in array_of_sets[set_v]:
>>>>>set_member_lookup[k] = set_u
>>>>sets[set_v] = None

***
