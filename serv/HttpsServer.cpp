#include "HttpsServer.h"

HttpsServer::HttpsServer(const std::string_view _cert, const std::string_view _prvt_key)
{
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	bd_sqlite = nullptr;
	listen_sock = INVALID_SOCKET;
	ssl_ctx = SSL_CTX_new(TLS_server_method());
	if (ssl_ctx)
	{
		SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_COMPRESSION | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
		SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
		if (SSL_CTX_use_certificate_file(ssl_ctx, _cert.data(), SSL_FILETYPE_PEM) <= 0)
		{
			SSL_CTX_free(ssl_ctx);
			std::cerr << "Failed certificate file\n";
			exit(EXIT_FAILURE);
		}
		if (SSL_CTX_use_PrivateKey_file(ssl_ctx, _prvt_key.data(), SSL_FILETYPE_PEM) <= 0)
		{
			SSL_CTX_free(ssl_ctx);
			std::cerr << "Failed private key file\n";
			exit(EXIT_FAILURE);
		}
	}
	else {
		SSL_CTX_free(ssl_ctx);
		std::cerr << "Error SSL_CTX_new\n";
		exit(EXIT_FAILURE);
	}
}
//------------------------------------------------------------------------------------
HttpsServer::HttpsServer(const std::string_view _cert, const std::string_view _prvt_key, std::string_view path_web)
	:HttpsServer::HttpsServer(_cert, _prvt_key)
{
	_path_web = path_web;
}
//-------------------------------------
HttpsServer::HttpsServer(const std::string_view _cert, const std::string_view _prvt_key,
std::string_view path_web, const std::string_view name_bd, std::vector<std::string>& fields)
	:HttpsServer::HttpsServer(_cert, _prvt_key, path_web)
{
	if (name_bd.size()) bd_sqlite = new Sqlite_(name_bd, fields);
}
//-------------------------------------------------------
HttpsServer::~HttpsServer()
{
	closesocket(listen_sock);
	SSL_CTX_free(ssl_ctx);
	if (bd_sqlite != nullptr)
	{
		delete bd_sqlite; bd_sqlite = nullptr;
	}
}
//----------------------------------------------------------
bool HttpsServer::Use(const std::string& method, const std::string& path, VoidFun f)
{
	RestUrl data_rest;
	data_rest.method = method;
	data_rest.path = path;
	arr_api_pairs.emplace_back(data_rest, std::move(f));
	return true;
}
//---------------------------------------------------------
SOCKET HttpsServer::Create_listen_socket(const int& port)
{
	SOCKET Client_socket = INVALID_SOCKET;
	SOCKET Listen_socket = INVALID_SOCKET;
#ifdef _WIN32
	WSADATA wsaData;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		std::cerr << "Failed WSAStartup\n";
		return EXIT_FAILURE;
	}
#endif
	ADDRINFO* addr_inf = nullptr; ;
	ADDRINFO hints = {};
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;
	int result = getaddrinfo(nullptr, (std::to_string(port)).c_str(), &hints, &addr_inf);
	if (result != 0) {
		std::cerr << "\ngetaddrinfo failed: " << result << "\n";
		WSACleanup();
		return EXIT_FAILURE;
	}
	Listen_socket = socket(addr_inf->ai_family, addr_inf->ai_socktype, addr_inf->ai_protocol);
	if (Listen_socket == INVALID_SOCKET) {
		std::cerr << "\nListen socket creation failed with error: " << WSAGetLastError() << "\n";
		freeaddrinfo(addr_inf);
		WSACleanup();
		return EXIT_FAILURE;
	}
	if (bind(Listen_socket, addr_inf->ai_addr, (int)addr_inf->ai_addrlen) == INVALID_SOCKET)
	{
		std::cerr << "\nBind failed with error: " << WSAGetLastError() << "\n";
		closesocket(Listen_socket);
		Listen_socket = INVALID_SOCKET;
		freeaddrinfo(addr_inf);
		WSACleanup();
		return  EXIT_FAILURE;
	}
	if (listen(Listen_socket, SOMAXCONN) == INVALID_SOCKET)
	{
		std::cerr << "\nListen failed with error: " << WSAGetLastError() << "\n";
		closesocket(Listen_socket);
		freeaddrinfo(addr_inf);
		WSACleanup();
		return EXIT_FAILURE;
	}
	return Listen_socket;
}
//-----------------------------------------------------------
HttpsServer::task_asyn HttpsServer::Connect_waiting(const int& port)
{
	listen_sock = Create_listen_socket(port);
	while (listen_sock != INVALID_SOCKET)
	{
		SOCKET client_sock = accept(listen_sock, nullptr, nullptr);
		if (client_sock == INVALID_SOCKET) {
			std::cerr << "\nUnable to accept\n";
			closesocket(client_sock);
			continue;
		}
		Client clnt(client_sock, ssl_ctx, arr_api_pairs, _path_web, bd_sqlite);
		co_await clnt.ExecutAsync();
	}
}
//-----------------------------------------------------------
bool HttpsServer::Listen(const int& port)
{
	std::jthread jth(
		[&]() {
			Connect_waiting(port);
		}
	);
	return true;
}
//----------------------------------------------------------
int HttpsServer::Client::Receive_data(SSL* ssl_temp)
{
	int rxlen = SSL_read(ssl_temp, (void*)Data_received.c_str(), SIZE_GET_REQ);
	Data_received.resize(rxlen + 1);
	if (rxlen > 0) {
		Data_received[rxlen] = '\0';
	}
	else {
		int error = SSL_get_error(ssl_temp, rxlen);
		if (error == SSL_ERROR_WANT_READ) {
			wait_for_socket(5, true);
			return -1;
		}
		else if (error == SSL_ERROR_WANT_WRITE) {
			wait_for_socket(5, false);
			return -1;
		}
		else {
			unsigned long err_code = ERR_get_error();
			char err_buf[256];
			ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
			std::cerr << "SSL_read error: " << err_buf << std::endl;
			return -1;
		}
	}
	return rxlen;
}
//------------------------------------------------------
int HttpsServer::Client::Send_data(SSL* ssl_temp, std::string& res)
{
	auto rxlen = SSL_write(ssl_temp, res.c_str(), (int)(res.length()));
#ifdef _DEBUG
	if (rxlen < 1)
	{
		ERR_print_errors_fp(stderr);
	}
#endif
	return rxlen;
}
//-------------------------------------------
HttpsServer::Client::Client(const SOCKET& sock, SSL_CTX* ssl_ctx, const arr_pairs& arr_pr, std::string& path_web)
{
	copy_socket = sock;
	SSL_CTX_up_ref(ssl_ctx);
	copy_ssl_ctx = ssl_ctx;
	std::copy(arr_pr.begin(), arr_pr.end(), std::back_inserter(copy_arr_api_pairs));
	path_web_cl = path_web;
}
//----------------------------------------------
HttpsServer::Client::Client(const SOCKET& sock, SSL_CTX* ssl_ctx, const arr_pairs& arr_pr, std::string& path_web, Sqlite_* sqlbd)
	:Client(sock, ssl_ctx, arr_pr, path_web)
{
	_sqlbd = sqlbd;
}
//---------------------------------------------------
int HttpsServer::Client::async_send_data(SSL* ssl_temp, const std::string& status, const std::string& content_type, const std::string& body)
{
	std::string resp = status + "\r\n"
		"Content-Type: " + content_type + "\r\n"
		"Content-Length: " + std::to_string(body.size()) + "\r\n"
		"Connection: close\r\n\r\n" +
		body;
	auto res = _send_data(ssl_temp, resp);
	return res.result();
}
//----------------------------------------------------------------------------
bool HttpsServer::Client::wait_for_socket(int timeout_sec, bool for_read)
{
	fd_set fds;
	struct timeval timeout;
	FD_ZERO(&fds);
	FD_SET(copy_socket, &fds);
	timeout.tv_sec = timeout_sec;
	timeout.tv_usec = 0;
	int result = select(copy_socket + 1, for_read ? &fds : nullptr, for_read ? nullptr : &fds, nullptr, &timeout);
	if (result > 0 && FD_ISSET(copy_socket, &fds)) {
		return true; // Сокет готов
	}
	else if (result == 0) {
		std::cerr << "Timeout while waiting for socket.\n";
	}
	else {
		std::cerr << "Error in select: \n";
	}
	return false;
}
//-----------------------------------------------------------------------------------------
int HttpsServer::Client::AcceptSSL(SSL* ssl)
{
	int ret = 0;
	while (true) {
		ret = SSL_accept(ssl);
		if (ret > 0) {
			break; 
		}
		int ssl_error = SSL_get_error(ssl, ret);
		if (ssl_error == SSL_ERROR_WANT_READ) {
			if (!wait_for_socket(5, true)) {
				break; 
			}
		}
		else if (ssl_error == SSL_ERROR_WANT_WRITE) {
			if (!wait_for_socket(5, false)) {
				break;
			}
		}
		else {
			unsigned long err_code = ERR_get_error();
			char err_buf[256];
			ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
			std::cerr << "SSL_accept error: " << err_buf << std::endl;
			break;
		}
	}
	return ret;
}
//-------------------------------------------------
void HttpsServer::Client::mode_socket_blocking(SOCKET& socket, bool mode) {
#ifdef _WIN32
	unsigned long mode1 = mode ? 0 : 1;
	if (ioctlsocket(socket, FIONBIO, &mode1) != 0) {
		std::cerr << "Failed to set non-blocking mode: " << WSAGetLastError() << std::endl;
		closesocket(socket);
		return;
	}
#else
	int flags = fcntl(socket, F_GETFL, 0);
	if (flags == -1) return;
	flags = mode ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
	if (fcntl(socket, F_SETFL, flags) == -1) {
		std::cerr << "Failed to set non-blocking mode" << std::endl;
		close(socket);
		return;
	}
#endif
}
//--------------------------------------------------------------------
std::string HttpsServer::Client::get_file_content(const std::string& path) {
	std::ifstream file(path, std::ios::binary);
	if (!file.is_open()) {
		return "";
	}
	std::stringstream buffer;
	buffer << file.rdbuf();
	return buffer.str();
}

std::string HttpsServer::Client::get_mime_type(const std::string& path) {
	std::map<std::string, std::string> mime_types = {
	{".html", "text/html"},
	{".css", "text/css"},
	{".js", "application/javascript"},
	{".json", "application/json"},
	{".png", "image/png"},
	{".jpg", "image/jpeg"},
	{".jpeg", "image/jpeg"},
	{".gif", "image/gif"},
	{".svg", "image/svg+xml"},
	{".woff", "font/woff"},
	{".woff2", "font/woff2"},
	{".ttf", "font/ttf"}
	};
	std::string extension = path.substr(path.find_last_of('.'));
	if (mime_types.find(extension) != mime_types.end()) {
		return mime_types[extension];
	}
	return "application/octet-stream";
}
//--------------------------------------------------------------------------------
int HttpsServer::Client::hndGetRequest(SSL* ssl_temp, const std::string& path, const std::pair<RestUrl, VoidFun>& p)
{
	int bytes_written = 0;
	if (path == p.first.path) {
		if (p.second) {
			void_func = p.second;
			void_func(Data_received, _resp);
			bytes_written = async_send_data(ssl_temp, "HTTP/1.1 200 OK", "text/html", _resp);
			return bytes_written;
		}
		else {
			std::string body;
			if (_sqlbd != nullptr) {
				_sqlbd->getItems(body);
				bytes_written = async_send_data(ssl_temp, "HTTP/1.1 200 OK", "application/json", body);
				return bytes_written;
			}
		}
	}
	else {
		if (!p.second) {
			std::string file_path = std::string(100, '\0');
			if (path == "/") {
				file_path = path_web_cl + "/index.html"; 
			}
			else
				file_path = path_web_cl + path;

			if (std::filesystem::exists(file_path)) {
				std::string content = get_file_content(file_path);
				std::string mime_type = get_mime_type(file_path);
				bytes_written = async_send_data(ssl_temp, "HTTP/1.1 200 OK", mime_type, content);
			}
			else {
				return bytes_written;
			}
		}
	}
	return bytes_written;
}
//-----------------------------------------------
void HttpsServer::Client::hndPostRequest(SSL* ssl_temp, const std::string& body, const std::string& path, const std::pair<RestUrl, VoidFun>& p)
{
	int bytes_written = 0;
	if (path == p.first.path) {
		if (p.second) {//if no empty
			void_func = p.second;
			void_func(Data_received, _resp);
			bytes_written = async_send_data(ssl_temp, "HTTP/1.1 200 OK", "application/json", _resp);
			return;
		}
		Json::CharReaderBuilder reader;
		Json::Value jsonData;
		std::istringstream sstream(body);
		std::string errs;
		Json::parseFromStream(reader, sstream, &jsonData, &errs);
		bool result = false;
		for (int i = 0; i < _sqlbd->_fields.size(); ++i) {
			if (jsonData.isMember(_sqlbd->_fields[i])) result = true;
			else result = false;
		}
		if (result) {
			std::vector<std::string> data_add;
			for (int i = 0; i < _sqlbd->_fields.size(); ++i)
			{
				data_add.emplace_back(jsonData[_sqlbd->_fields[i]].asString());
			}
			std::string response;

			int id_last = _sqlbd->addItem(data_add, response);
			if (response == "Success") {
				response.clear();
				Json::Value response_jsn;
				response_jsn["id"] = id_last;
				for (int i = 0; i < _sqlbd->_fields.size(); ++i)
				{
					response_jsn[_sqlbd->_fields[i]] = data_add[i];
				}
				Json::StreamWriterBuilder writer;
				response = Json::writeString(writer, response_jsn);
			}
			bytes_written = async_send_data(ssl_temp, "HTTP/1.1 200 OK", "application/json", response);
		}
	}
	else return;
}
//----------------------------------------------------------
void HttpsServer::Client::hndDeleteRequest(SSL* ssl_temp, const std::string& path, const std::pair<RestUrl, VoidFun>& p)
{
	int bytes_written = 0;
	std::string path_temp = path.substr(0, path.find_last_of("/"));;

	if (path_temp == p.first.path) {
		if (p.second) {//if no empty
			void_func = p.second;
			void_func(Data_received, _resp);
			bytes_written = async_send_data(ssl_temp, "HTTP/1.1 200 OK", "application/json", _resp);
			return;
		}
		int id = std::stoi(path.substr(path.find_last_of("/") + 1));  // Извлекаем id из пути
		std::string response;
		_sqlbd->deleteItem(id, response);
		std::string responseHeader = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n";
		bytes_written = async_send_data(ssl_temp, "HTTP/1.1 200 OK", "application/json", response);
	}
	else return;
}
//--------------------------------------------------------------------------------------
void HttpsServer::Client::execution()
{
	mode_socket_blocking(copy_socket, true);
	SSL* ssl_temp = SSL_new(copy_ssl_ctx);
	SSL_set_fd(ssl_temp, (int)copy_socket);

	if (AcceptSSL(ssl_temp) > 0) {
		auto reseiv = Receive_data(ssl_temp);
		if (reseiv) {
			std::istringstream request_stream(Data_received);
			std::string method, path, protocol;
			request_stream >> method >> path >> protocol;
			std::string url_base = path.substr(0, path.find_last_of("/"));
			std::string end_point = path.substr(path.find_last_of("/"), path.size());
			std::string body = Data_received.substr(Data_received.find("\r\n\r\n") + 4);
			int bytes_written = 0;
			for (std::pair<RestUrl, VoidFun>& p : copy_arr_api_pairs)
			{
				//bytes_written = 0;
				if (method == "GET" && p.first.method == "GET") {
					bytes_written = hndGetRequest(ssl_temp, path, p);
				}
				else if (method == "POST" && p.first.method == "POST") {
					hndPostRequest(ssl_temp, body, path, p);
				}
				else if (method == "DELETE" && p.first.method == "DELETE") {
					hndDeleteRequest(ssl_temp, path, p);
				}
				else continue;
			}
			if (!bytes_written) {
				std::string error_body = "<html><body><h1 align=\"center\">404 Page not found</h1></body></html>";
				bytes_written = async_send_data(ssl_temp, "HTTP/1.1 404 Not found", "text/html", error_body);
			}
		}
		SSL_shutdown(ssl_temp);
		SSL_free(ssl_temp);
		closesocket(copy_socket);
		return;
	}
	SSL_shutdown(ssl_temp);
	SSL_free(ssl_temp);
	closesocket(copy_socket);
}
//-------------------------------------------------------------
HttpsServer::ret_task_asyn HttpsServer::Client::_send_data(SSL* ssl_temp, const std::string& resp)
{
	int offset = 0, sent_bytes = 0;
	while (offset < resp.size()) {
		sent_bytes = co_await HttpsServer::Client::AwaitSend(*this, ssl_temp, resp.c_str() + offset);
		if (sent_bytes > 0) offset += sent_bytes;
		else {
			int ssl_error = SSL_get_error(ssl_temp, sent_bytes);
			if (ssl_error == SSL_ERROR_WANT_WRITE) {
				if (!wait_for_socket(5, false)) {
					std::cerr << "Timeout while waiting for SSL_write readiness.\n";
					co_return -1; 
				}
			}
			else if (ssl_error == SSL_ERROR_WANT_READ) {
				if (!wait_for_socket(5, true)) {
					std::cerr << "Timeout while waiting for SSL_read readiness during SSL_write.\n";
					co_return -1; 
				}
			}
			else {
				unsigned long err_code = ERR_get_error();
				char err_buf[256];
				ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
				std::cerr << "SSL_write error: " << err_buf << std::endl;
				co_return -1; 
			}
			if (sent_bytes < 1) co_return sent_bytes;
		}
	}
	co_return sent_bytes;
}
//------------------------------------------------------------
HttpsServer::Client::Await HttpsServer::Client::ExecutAsync()
{
	return HttpsServer::Client::Await(*this);
}
//-----------------------------------------------------------------------------
void HttpsServer::Client::Await::await_suspend(std::coroutine_handle<> handle) noexcept
{
	client->execution();
	handle.resume();
}
//------------------------------------------------------
void HttpsServer::Client::AwaitSend::await_suspend(std::coroutine_handle<> handle) noexcept
{
	Quant_send = client->Send_data(_ssl_temp, _resp);
	handle.resume();
}
//-------------------------------------
HttpsServer::Sqlite_::Sqlite_(std::string_view db_name, std::vector<std::string>& fields)
	: db(nullptr), dbName(db_name), _fields(fields)
{
	int res = sqlite3_open(dbName.c_str(), &db);
	if (res) {
		std::cerr << "Database opening error: " << sqlite3_errmsg(db) << std::endl;
	}
	else {
		std::cout << "Successfully opened the database: " << dbName << std::endl;
		std::string createTableSQL = R"(
            CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT);)";

		auto insert_name_field = [&](std::string& text) {
			createTableSQL.insert(createTableSQL.length() - 2, +",\n\t" + text + " TEXT NOT NULL");
			};

		for (auto& i : _fields)
		{
			insert_name_field(i);
		}
		char* errMessage = 0;
		res = sqlite3_exec(db, createTableSQL.c_str(), 0, 0, &errMessage);
		if (res != SQLITE_OK) {
			std::cerr << "Error creating table: " << errMessage << std::endl;
			sqlite3_free(errMessage);
		}
		else {
			std::cout << "Table successfully created!" << std::endl;
		}
		sqlite3_close(db);
	}
}
//---------------------------------
HttpsServer::Sqlite_::~Sqlite_()
{
	if (db) {
		int res = sqlite3_close(db);
		if (res == SQLITE_OK) {
			std::cout << "Successfully close the database: " << dbName << std::endl;
		}
		else {
			std::cerr << "Database close error:: " << sqlite3_errmsg(db) << std::endl;
		}
	}
}
//--------------------------------------------
int HttpsServer::Sqlite_::executeSQL(const std::string& sql, std::string& result)
{
	char* errMessage = 0;
	int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errMessage);
	if (rc != SQLITE_OK) {
		result = "SQL Error: " + std::string(errMessage);
		sqlite3_free(errMessage);
	}
	else {
		result = "Success";
	}
	return rc;
}
//-------------------------------------------
void HttpsServer::Sqlite_::resetAutoIncrement(sqlite3* db, const std::string& tableName) {
	std::string resetSQL = "DELETE FROM sqlite_sequence WHERE name = '" + tableName + "';";
	char* errMessage = 0;
	int rc = sqlite3_exec(db, resetSQL.c_str(), nullptr, nullptr, &errMessage);

	if (rc != SQLITE_OK) {
		std::cerr << "Error resetting AUTOINCREMENT: " << errMessage << std::endl;
		sqlite3_free(errMessage);
	}
	else {
		std::cout << "AUTOINCREMENT reset for table: " << tableName << std::endl;
	}
}
//---------------------------------------------
int HttpsServer::Sqlite_::addItem(std::vector<std::string>& data_fields, std::string& response)
{
	sqlite3_open(dbName.c_str(), &db);
	resetAutoIncrement(db, "items");
	std::string sql = "INSERT INTO items (";
	for (int i = 0; i < _fields.size(); ++i)
	{
		if (i < (_fields.size() - 1))
			sql.insert(sql.length(), _fields[i] + ", ");
		else
			sql.insert(sql.length(), _fields[i] + ")");
	}
	sql = sql.insert(sql.length(), " VALUES (");

	for (int i = 0; i < data_fields.size(); ++i)
	{
		if (i < (data_fields.size() - 1))
			sql.insert(sql.length(), "'" + data_fields[i] + "', ");
		else
			sql.insert(sql.length(), "'" + data_fields[i] + "');");
	}
	executeSQL(sql, response);
	int lastInsertId = sqlite3_last_insert_rowid(db);
	sqlite3_close(db);
	return lastInsertId;
}
//---------------------------------------------------
void HttpsServer::Sqlite_::deleteItem(int id, std::string& response) {
	sqlite3_open(dbName.c_str(), &db);
	std::string sql = "DELETE FROM items WHERE id = " + std::to_string(id) + ";";
	executeSQL(sql, response);
	sqlite3_close(db);
}
//-------------------------------------------
void HttpsServer::Sqlite_::getItems(std::string& response) {
	sqlite3_open(dbName.c_str(), &db);
	std::string sql = "SELECT * FROM items;";
	sqlite3_stmt* stmt;
	int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
	if (rc != SQLITE_OK) {
		response = "Error preparing statement";
		sqlite3_close(db);
		return;
	}
	Json::Value items(Json::arrayValue);
	while (sqlite3_step(stmt) == SQLITE_ROW) {

		Json::Value item;
		item["id"] = sqlite3_column_int(stmt, 0);
		for (int i = 0; i < _fields.size(); ++i)
		{
			item[_fields[i]] = std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, i + 1)));
		}
		items.append(item);
	}
	Json::StreamWriterBuilder writer;
	response = Json::writeString(writer, items); 
	sqlite3_finalize(stmt);
	sqlite3_close(db);
}
