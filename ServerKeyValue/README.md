## Simple TCP server in C++ 20, which is a simple key-value store in a PostgerSQL database. 

Asynchronous queries using boost.asio and coroutine are implemented.
The server can be checked with the netcat utility:
```cpp
 echo -n '{“request”: 'read', 'key': 'some_key'}' | nc 127.0.0.1 8120
```
 or
```cpp 
 echo -n '{“request”: “write”, ‘key’: ‘some_key’, ‘value’: ‘some_value’}' | nc 127.0.0.1 8120
```
Example code
```cpp 
 std::string base_config = std::string("postgresql://postgres:123@localhost:8121/test");
 ServerKeyValue srv(base_config);
 srv.Listen(8120);
```
The 'catch' is used for testing

