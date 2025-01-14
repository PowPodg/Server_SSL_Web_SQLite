# HTTPS server with integrated SQLite database using stackless coroutines (C++20) 

### Simplified cross-platform (Windows, Linux) http server for ssl support and with integrated SQLite database 
### This project shows an example of using stackless coroutines (including nested coroutines) for client connections

### Usage variants:
> #### 1.
```cpp
	HttpsServer srv("cert.pem", "key.pem");
	srv.Use("GET","/1", [&](const std::string& req, std::string& resp) {
        resp = "Page 1";
		cout << req;
		});
	srv.Use("GET", "/2", [&](const std::string& req, std::string& resp) {
		resp = "Page 2";
		cout << req;
		});
```
> #### 2. Web interface usage:
```cpp
	std::string path_web_inerface = "web_interface/build";
	HttpsServer srv("cert.pem", "key.pem", path_web_inerface);
	srv.Use("GET", "*", nullptr);
```
> #### 3. SQLite datfbase usage: (for the web interface variant presented in 'web_interface/build')
```cpp
       std::string base_name = "base_sql.db";
       vector <std::string> fields_base = { "name", "email" };
       HttpsServer srv("cert.pem", "key.pem", path_web_inerface, base_name, fields_base);
       srv.Use("GET",    "/api/items", nullptr);
       srv.Use("POST",   "/api/items", nullptr);
       srv.Use("DELETE", "/api/items/id", nullptr);
```
> #### A variant of a dynamically modifiable web interface built with React: (web_interface/build)

<p align="center">
  <img src="web_interface/web_inreface.png" width="700">
</p>
