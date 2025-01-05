#pragma once
#include <iostream>
#include <string>
#include <sstream>
#include <functional>
#include <thread>
#include <coroutine>
#include "sqlite/sqlite3.h"
#include "json/json/json.h"
#include <vector>
#include <fstream>
#include <filesystem>
#include <fcntl.h>

#include <openssl/ssl.h>
#include <openssl/err.h>


#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else 
using SOCKET = int;
#define INVALID_SOCKET  (-1)
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
inline int WSACleanup() { return 0; }
inline int closesocket(SOCKET sock) { return close(sock); }
using ADDRINFO = struct addrinfo;
#define WSAGetLastError() (errno)
#endif

//----------------------
class HttpsServer
{
	struct RestUrl {
		std::string method;
		std::string path;
	};
	static const int SIZE_GET_REQ = 4096;

	struct task_asyn
	{
		struct promise_type
		{
			task_asyn get_return_object() { return task_asyn{}; }
			std::suspend_never initial_suspend() noexcept { return {}; }
			std::suspend_never final_suspend() noexcept { return {}; }
			void return_void() {}
			void unhandled_exception() {}
		};
	};
	//---------------------------------------------------
	class ret_task_asyn
	{
	public:
		struct promise_type
		{
			int _result;
			ret_task_asyn get_return_object() {
				return ret_task_asyn{ std::coroutine_handle<promise_type>::from_promise(*this) };
			}
			std::suspend_never initial_suspend() noexcept { return {}; }
			std::suspend_always final_suspend() noexcept { return {}; }
			void return_value(int res) noexcept { _result = res; }
			void unhandled_exception() { std::terminate(); }
		};
		int result() { return handle_.promise()._result; }
		~ret_task_asyn() { if (handle_) handle_.destroy(); }
	private:
		ret_task_asyn(std::coroutine_handle<promise_type> handle) : handle_(handle) {}
		std::coroutine_handle<promise_type> handle_;
	};
	//-------------
	using VoidFun = std::function<void(const std::string&, std::string&)>;
	using arr_pairs = std::vector<std::pair<RestUrl, VoidFun>>;
	arr_pairs arr_api_pairs;
	//-----------
	class Sqlite_
	{
	public:
		explicit Sqlite_(std::string_view, std::vector<std::string>&);
		~Sqlite_();
		int executeSQL(const std::string&, std::string&);
		int addItem(std::vector<std::string>&, std::string&);
		void deleteItem(int, std::string&);
		void getItems(std::string&);
		void resetAutoIncrement(sqlite3*, const std::string&);
		std::vector<std::string> _fields;
	private:
		sqlite3* db;
		std::string dbName;
	};

	Sqlite_* bd_sqlite;
	//----------------------------------------
	SSL_CTX* ssl_ctx;
	SOCKET listen_sock;
	SOCKET Create_listen_socket(const int&);
	//--------
	class Client {
	private:
		std::string rest_get = "GET ";
		std::string rest_options = "OPTIONS ";
		VoidFun void_func;
		std::string Data_received = std::string(SIZE_GET_REQ, '\0');
		int Receive_data(SSL*);
		std::string_view Analys_expression();
		int Send_data(SSL*, std::string&);
		SOCKET copy_socket;
		SSL_CTX* copy_ssl_ctx;
		arr_pairs copy_arr_api_pairs;
		std::string _resp = std::string(SIZE_GET_REQ, '\0');;
		//---------
		class Await {
		public:
			Await(Client& cl) : client(std::addressof(cl)) {}
			bool await_ready() const noexcept { return false; }
			void await_suspend(std::coroutine_handle<>) noexcept;
			void await_resume() const noexcept {}
		private:
			Client* client = nullptr;
		};
		//-----------
		class AwaitSend {
		public:
			bool await_ready() const noexcept { return false; }
			void await_suspend(std::coroutine_handle<>) noexcept;
			int await_resume() const noexcept { return std::move(Quant_send); }
			AwaitSend(Client& cl, SSL* ssl_temp, const std::string& resp) : client(std::addressof(cl)), _ssl_temp(ssl_temp), _resp(resp) {}
		private:
			Client* client = nullptr;
			SSL* _ssl_temp = nullptr;;
			std::string _resp = std::string(SIZE_GET_REQ, '\0');;
			int Quant_send = 0;
		};
		//---------------------------------------------	
		void hndPostRequest(SSL*, const std::string&, const std::string&, const std::pair<RestUrl, VoidFun>&);
		int hndGetRequest(SSL*,const std::string&, const std::pair<RestUrl, VoidFun>&);
		void hndDeleteRequest(SSL*, const std::string&, const std::pair<RestUrl, VoidFun>&);
		std::string get_mime_type(const std::string&);
		std::string get_file_content(const std::string&);
		void mode_socket_blocking(SOCKET&, bool);
		bool wait_for_socket(int, bool);
		int AcceptSSL(SSL*);
		void execution();
		ret_task_asyn _send_data(SSL*, const std::string&);
	public:
		Await ExecutAsync();
		Client(const SOCKET&, SSL_CTX*, const arr_pairs&, std::string&);
		Client(const SOCKET&, SSL_CTX*, const arr_pairs&, std::string&, Sqlite_*);
		int async_send_data(SSL*, const std::string&, const std::string&, const std::string&);
		~Client() { SSL_CTX_free(copy_ssl_ctx); }
	private:
		Sqlite_* _sqlbd;
		std::string path_web_cl;
	};
	//-------
	task_asyn Connect_waiting(const int& port);
public:
	HttpsServer(const std::string_view, const std::string_view);
	HttpsServer(const std::string_view, const std::string_view, std::string_view);
	HttpsServer(const std::string_view, const std::string_view,
		std::string_view, const std::string_view, std::vector<std::string>&);
	~HttpsServer();
	bool Use(const std::string&, const std::string&, VoidFun);
	bool Listen(const int& port);
private:
	std::string _path_web;
};

