#include "HttpsServerCoroutine.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <chrono>
#include <cstring>
#include <thread>

// ---------------- Scheduler ----------------

void HttpsServerCoroutine::Scheduler::schedule(std::coroutine_handle<> handle)
{
    if (handle) {
        ready_.push(handle);
    }
}

void HttpsServerCoroutine::Scheduler::wait_read(SOCKET socket, std::coroutine_handle<> handle)
{
    if (handle) {
        read_waiters_[socket] = handle;
    }
}

void HttpsServerCoroutine::Scheduler::wait_write(SOCKET socket, std::coroutine_handle<> handle)
{
    if (handle) {
        write_waiters_[socket] = handle;
    }
}

void HttpsServerCoroutine::Scheduler::run_ready()
{
    const std::size_t count = ready_.size();

    for (std::size_t i = 0; i < count; ++i) {
        auto handle = ready_.front();
        ready_.pop();

        if (handle && !handle.done()) {
            handle.resume();
        }
    }
}

void HttpsServerCoroutine::Scheduler::poll_io(int timeout_ms)
{
    if (read_waiters_.empty() && write_waiters_.empty()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(timeout_ms));
        return;
    }

    fd_set read_set;
    fd_set write_set;

    FD_ZERO(&read_set);
    FD_ZERO(&write_set);

    SOCKET max_socket = 0;

    for (const auto& [socket, handle] : read_waiters_) {
        FD_SET(socket, &read_set);
        if (socket > max_socket) {
            max_socket = socket;
        }
    }

    for (const auto& [socket, handle] : write_waiters_) {
        FD_SET(socket, &write_set);
        if (socket > max_socket) {
            max_socket = socket;
        }
    }

    timeval timeout{};
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;

#ifdef _WIN32
    const int result = select(0, &read_set, &write_set, nullptr, &timeout);
#else
    const int result = select(max_socket + 1, &read_set, &write_set, nullptr, &timeout);
#endif

    if (result <= 0) {
        return;
    }

    std::vector<SOCKET> ready_read;
    std::vector<SOCKET> ready_write;

    for (const auto& [socket, handle] : read_waiters_) {
        if (FD_ISSET(socket, &read_set)) {
            ready_read.push_back(socket);
        }
    }

    for (const auto& [socket, handle] : write_waiters_) {
        if (FD_ISSET(socket, &write_set)) {
            ready_write.push_back(socket);
        }
    }

    for (SOCKET socket : ready_read) {
        auto it = read_waiters_.find(socket);
        if (it != read_waiters_.end()) {
            schedule(it->second);
            read_waiters_.erase(it);
        }
    }

    for (SOCKET socket : ready_write) {
        auto it = write_waiters_.find(socket);
        if (it != write_waiters_.end()) {
            schedule(it->second);
            write_waiters_.erase(it);
        }
    }
}

bool HttpsServerCoroutine::Scheduler::has_work() const
{
    return !ready_.empty() || !read_waiters_.empty() || !write_waiters_.empty();
}

// ---------------- Awaiters ----------------

void HttpsServerCoroutine::WaitRead::await_suspend(std::coroutine_handle<> handle) noexcept
{
    scheduler_.wait_read(socket_, handle);
}

void HttpsServerCoroutine::WaitWrite::await_suspend(std::coroutine_handle<> handle) noexcept
{
    scheduler_.wait_write(socket_, handle);
}

void HttpsServerCoroutine::YieldToServer::await_suspend(std::coroutine_handle<> handle) noexcept
{
    scheduler_.schedule(handle);
}

// ---------------- HttpsServerCoroutine ----------------

HttpsServerCoroutine::HttpsServerCoroutine(std::string_view cert, std::string_view private_key)
{
#ifdef _WIN32
    WSADATA wsaData{};
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Failed WSAStartup\n";
        std::exit(EXIT_FAILURE);
    }
#endif

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ssl_ctx = SSL_CTX_new(TLS_server_method());

    if (!ssl_ctx) {
        std::cerr << "Error SSL_CTX_new\n";
        std::exit(EXIT_FAILURE);
    }

    SSL_CTX_set_options(
        ssl_ctx,
        SSL_OP_NO_COMPRESSION | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
    );

    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);

    if (SSL_CTX_use_certificate_file(ssl_ctx, cert.data(), SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Failed certificate file\n";
        SSL_CTX_free(ssl_ctx);
        ssl_ctx = nullptr;
        std::exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, private_key.data(), SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Failed private key file\n";
        SSL_CTX_free(ssl_ctx);
        ssl_ctx = nullptr;
        std::exit(EXIT_FAILURE);
    }
}

HttpsServerCoroutine::HttpsServerCoroutine(
    std::string_view cert,
    std::string_view private_key,
    std::string_view path_web_in
)
    : HttpsServerCoroutine(cert, private_key)
{
    path_web = std::string(path_web_in);
}

HttpsServerCoroutine::HttpsServerCoroutine(
    std::string_view cert,
    std::string_view private_key,
    std::string_view path_web_in,
    std::string_view name_bd,
    std::vector<std::string>& fields
)
    : HttpsServerCoroutine(cert, private_key, path_web_in)
{
    if (!name_bd.empty()) {
        bd_sqlite = std::make_unique<Sqlite_>(name_bd, fields);
    }
}

HttpsServerCoroutine::~HttpsServerCoroutine()
{
    Stop();
    active_sessions_.clear();

    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
        ssl_ctx = nullptr;
    }

    WSACleanup();
}

bool HttpsServerCoroutine::Use(const std::string& method, const std::string& path, VoidFun f)
{
    RestUrl data_rest;
    data_rest.method = method;
    data_rest.path = path;
    arr_api_pairs.emplace_back(data_rest, std::move(f));
    return true;
}

void HttpsServerCoroutine::SetServiceFunction(ServiceFun f)
{
    service_fun = std::move(f);
}

bool HttpsServerCoroutine::Listen(const int& port)
{
    listen_sock = Create_listen_socket(port);

    if (listen_sock == INVALID_SOCKET) {
        return false;
    }

    SetSocketBlocking(listen_sock, false);
    running = true;

    while (running) {
        TryAcceptClients();
        scheduler_.run_ready();
        CleanupFinishedSessions();
        DoServiceWork();
        scheduler_.poll_io(10);
    }

    return true;
}

void HttpsServerCoroutine::Stop()
{
    running = false;

    if (listen_sock != INVALID_SOCKET) {
        CloseSocket(listen_sock);
        listen_sock = INVALID_SOCKET;
    }
}

SOCKET HttpsServerCoroutine::Create_listen_socket(const int& port)
{
    ADDRINFO* addr_inf = nullptr;
    ADDRINFO hints{};

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    const int result = getaddrinfo(nullptr, std::to_string(port).c_str(), &hints, &addr_inf);

    if (result != 0) {
        std::cerr << "getaddrinfo failed: " << result << "\n";
        return INVALID_SOCKET;
    }

    SOCKET listen_socket = socket(addr_inf->ai_family, addr_inf->ai_socktype, addr_inf->ai_protocol);

    if (listen_socket == INVALID_SOCKET) {
        std::cerr << "Listen socket creation failed with error: " << WSAGetLastError() << "\n";
        freeaddrinfo(addr_inf);
        return INVALID_SOCKET;
    }

    int opt = 1;
    setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

    if (bind(listen_socket, addr_inf->ai_addr, static_cast<int>(addr_inf->ai_addrlen)) == SOCKET_ERROR) {
        std::cerr << "Bind failed with error: " << WSAGetLastError() << "\n";
        CloseSocket(listen_socket);
        freeaddrinfo(addr_inf);
        return INVALID_SOCKET;
    }

    freeaddrinfo(addr_inf);

    if (listen(listen_socket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen failed with error: " << WSAGetLastError() << "\n";
        CloseSocket(listen_socket);
        return INVALID_SOCKET;
    }

    return listen_socket;
}

void HttpsServerCoroutine::TryAcceptClients()
{
    while (running && listen_sock != INVALID_SOCKET) {
        SOCKET client_sock = accept(listen_sock, nullptr, nullptr);

        if (client_sock == INVALID_SOCKET) {
            if (!IsWouldBlock()) {
                std::cerr << "Unable to accept, error: " << WSAGetLastError() << "\n";
            }
            return;
        }

        SetSocketBlocking(client_sock, false);

        active_sessions_.push_back(HandleClient(client_sock));
        active_sessions_.back().start();
    }
}

HttpsServerCoroutine::Task HttpsServerCoroutine::HandleClient(SOCKET client_sock)
{
    SSL* ssl = SSL_new(ssl_ctx);

    if (!ssl) {
        CloseSocket(client_sock);
        co_return;
    }

    SSL_set_fd(ssl, static_cast<int>(client_sock));

    while (true) {
        const int ret = SSL_accept(ssl);

        if (ret == 1) {
            break;
        }

        const int err = SSL_get_error(ssl, ret);

        if (err == SSL_ERROR_WANT_READ) {
            co_await WaitRead(scheduler_, client_sock);
            continue;
        }

        if (err == SSL_ERROR_WANT_WRITE) {
            co_await WaitWrite(scheduler_, client_sock);
            continue;
        }

        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        CloseSocket(client_sock);
        co_return;
    }

    co_await YieldToServer(scheduler_);


    std::string request;
    request.reserve(SIZE_GET_REQ);

    while (!IsHttpRequestComplete(request)) {
        char buffer[SIZE_GET_REQ]{};

        const int ret = SSL_read(ssl, buffer, sizeof(buffer));

        if (ret > 0) {
            request.append(buffer, static_cast<std::size_t>(ret));

            if (request.size() > MAX_HTTP_REQUEST_SIZE) {
                const std::string response = MakeHttpResponse(
                    "HTTP/1.1 413 Payload Too Large",
                    "text/plain",
                    "Request too large"
                );

                std::size_t offset = 0;
                while (offset < response.size()) {
                    const int written = SSL_write(
                        ssl,
                        response.data() + offset,
                        static_cast<int>(response.size() - offset)
                    );

                    if (written > 0) {
                        offset += static_cast<std::size_t>(written);
                        continue;
                    }

                    const int err = SSL_get_error(ssl, written);
                    if (err == SSL_ERROR_WANT_READ) {
                        co_await WaitRead(scheduler_, client_sock);
                        continue;
                    }
                    if (err == SSL_ERROR_WANT_WRITE) {
                        co_await WaitWrite(scheduler_, client_sock);
                        continue;
                    }
                    break;
                }

                SSL_shutdown(ssl);
                SSL_free(ssl);
                CloseSocket(client_sock);
                co_return;
            }

            co_await YieldToServer(scheduler_);
            continue;
        }

        const int err = SSL_get_error(ssl, ret);

        if (err == SSL_ERROR_WANT_READ) {
            co_await WaitRead(scheduler_, client_sock);
            continue;
        }

        if (err == SSL_ERROR_WANT_WRITE) {
            co_await WaitWrite(scheduler_, client_sock);
            continue;
        }

        SSL_free(ssl);
        CloseSocket(client_sock);
        co_return;
    }

    co_await YieldToServer(scheduler_);

    std::optional<std::string> response_opt = BuildResponseFromRequest(request);

    std::string response = response_opt.value_or(
        MakeHttpResponse(
            "HTTP/1.1 500 Internal Server Error",
            "text/plain",
            "Internal Server Error"
        )
    );

    co_await YieldToServer(scheduler_);

    std::size_t offset = 0;

    while (offset < response.size()) {
        const int ret = SSL_write(
            ssl,
            response.data() + offset,
            static_cast<int>(response.size() - offset)
        );

        if (ret > 0) {
            offset += static_cast<std::size_t>(ret);
            co_await YieldToServer(scheduler_);
            continue;
        }

        const int err = SSL_get_error(ssl, ret);

        if (err == SSL_ERROR_WANT_READ) {
            co_await WaitRead(scheduler_, client_sock);
            continue;
        }

        if (err == SSL_ERROR_WANT_WRITE) {
            co_await WaitWrite(scheduler_, client_sock);
            continue;
        }

        break;
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    CloseSocket(client_sock);
}

bool HttpsServerCoroutine::SetSocketBlocking(SOCKET socket, bool blocking)
{
#ifdef _WIN32
    u_long mode = blocking ? 0 : 1;
    return ioctlsocket(socket, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(socket, F_GETFL, 0);
    if (flags == -1) {
        return false;
    }

    if (blocking) {
        flags &= ~O_NONBLOCK;
    }
    else {
        flags |= O_NONBLOCK;
    }

    return fcntl(socket, F_SETFL, flags) != -1;
#endif
}

bool HttpsServerCoroutine::IsWouldBlock() const
{
#ifdef _WIN32
    const int err = WSAGetLastError();
    return err == WSAEWOULDBLOCK;
#else
    return errno == EWOULDBLOCK || errno == EAGAIN;
#endif
}

std::optional<std::string> HttpsServerCoroutine::BuildResponseFromRequest(const std::string& request)
{
    std::istringstream request_stream(request);
    std::string method;
    std::string path;
    std::string protocol;

    request_stream >> method >> path >> protocol;

    const std::size_t body_pos = request.find("\r\n\r\n");
    std::string body;

    if (body_pos != std::string::npos) {
        body = request.substr(body_pos + 4);
    }

    if (method == "GET") {
        return HandleGet(request, path);
    }

    if (method == "POST") {
        return HandlePost(request, path, body);
    }

    if (method == "DELETE") {
        return HandleDelete(request, path);
    }

    return MakeHttpResponse(
        "HTTP/1.1 405 Method Not Allowed",
        "text/plain",
        "Method Not Allowed"
    );
}

std::string HttpsServerCoroutine::HandleGet(const std::string& request, const std::string& path)
{
    for (const auto& p : arr_api_pairs) {
        if (p.first.method != "GET") {
            continue;
        }

        if (path == p.first.path) {
            if (p.second) {
                std::string response_body;
                p.second(request, response_body);
                return MakeHttpResponse("HTTP/1.1 200 OK", "application/json", response_body);
            }

            if (bd_sqlite) {
                std::string body;
                bd_sqlite->getItems(body);
                return MakeHttpResponse("HTTP/1.1 200 OK", "application/json", body);
            }

            return MakeHttpResponse("HTTP/1.1 400 Bad Request", "text/plain", "Database is not configured");
        }
    }

    std::string target = path;

    if (target == "/") {
        target = "/index.html";
    }

    if (target.find("..") != std::string::npos) {
        return MakeHttpResponse("HTTP/1.1 400 Bad Request", "text/plain", "Bad path");
    }

    const std::string file_path = path_web + target;

    if (!std::filesystem::exists(file_path) || !std::filesystem::is_regular_file(file_path)) {
        return MakeHttpResponse(
            "HTTP/1.1 404 Not Found",
            "text/html",
            "<html><body><h1 align=\"center\">404 Page not found</h1></body></html>"
        );
    }

    return MakeHttpResponse(
        "HTTP/1.1 200 OK",
        GetMimeType(file_path),
        GetFileContent(file_path)
    );
}

std::string HttpsServerCoroutine::HandlePost(
    const std::string& request,
    const std::string& path,
    const std::string& body
)
{
    for (const auto& p : arr_api_pairs) {
        if (p.first.method != "POST") {
            continue;
        }

        if (path != p.first.path) {
            continue;
        }

        if (p.second) {
            std::string response_body;
            p.second(request, response_body);
            return MakeHttpResponse("HTTP/1.1 200 OK", "application/json", response_body);
        }

        if (!bd_sqlite) {
            return MakeHttpResponse("HTTP/1.1 400 Bad Request", "text/plain", "Database is not configured");
        }

        Json::CharReaderBuilder reader;
        Json::Value jsonData;
        std::istringstream sstream(body);
        std::string errs;

        if (!Json::parseFromStream(reader, sstream, &jsonData, &errs)) {
            return MakeHttpResponse("HTTP/1.1 400 Bad Request", "text/plain", errs);
        }

        bool has_all_fields = true;

        for (std::size_t i = 0; i < bd_sqlite->_fields.size(); ++i) {
            if (!jsonData.isMember(bd_sqlite->_fields[i])) {
                has_all_fields = false;
                break;
            }
        }

        if (!has_all_fields) {
            return MakeHttpResponse("HTTP/1.1 400 Bad Request", "text/plain", "Missing JSON field");
        }

        std::vector<std::string> data_add;

        for (std::size_t i = 0; i < bd_sqlite->_fields.size(); ++i) {
            data_add.emplace_back(jsonData[bd_sqlite->_fields[i]].asString());
        }

        std::string response;
        const int id_last = bd_sqlite->addItem(data_add, response);

        if (response == "Success") {
            response.clear();
            Json::Value response_json;
            response_json["id"] = id_last;

            for (std::size_t i = 0; i < bd_sqlite->_fields.size(); ++i) {
                response_json[bd_sqlite->_fields[i]] = data_add[i];
            }

            Json::StreamWriterBuilder writer;
            response = Json::writeString(writer, response_json);
        }

        return MakeHttpResponse("HTTP/1.1 200 OK", "application/json", response);
    }

    return MakeHttpResponse("HTTP/1.1 404 Not Found", "text/plain", "404 Not Found");
}

std::string HttpsServerCoroutine::HandleDelete(const std::string& request, const std::string& path)
{
    for (const auto& p : arr_api_pairs) {
        if (p.first.method != "DELETE") {
            continue;
        }

        const std::string path_base = path.substr(0, path.find_last_of('/'));

        if (path_base != p.first.path) {
            continue;
        }

        if (p.second) {
            std::string response_body;
            p.second(request, response_body);
            return MakeHttpResponse("HTTP/1.1 200 OK", "application/json", response_body);
        }

        if (!bd_sqlite) {
            return MakeHttpResponse("HTTP/1.1 400 Bad Request", "text/plain", "Database is not configured");
        }

        const std::string id_text = path.substr(path.find_last_of('/') + 1);
        int id = 0;

        try {
            id = std::stoi(id_text);
        }
        catch (...) {
            return MakeHttpResponse("HTTP/1.1 400 Bad Request", "text/plain", "Bad id");
        }

        std::string response;
        bd_sqlite->deleteItem(id, response);

        return MakeHttpResponse("HTTP/1.1 200 OK", "application/json", response);
    }

    return MakeHttpResponse("HTTP/1.1 404 Not Found", "text/plain", "404 Not Found");
}

std::string HttpsServerCoroutine::MakeHttpResponse(
    const std::string& status,
    const std::string& content_type,
    const std::string& body
) const
{
    return status + "\r\n"
        "Content-Type: " + content_type + "\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n"
        "Connection: close\r\n\r\n" +
        body;
}

std::string HttpsServerCoroutine::GetMimeType(const std::string& path) const
{
    static const std::map<std::string, std::string> mime_types = {
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

    const std::size_t pos = path.find_last_of('.');

    if (pos == std::string::npos) {
        return "application/octet-stream";
    }

    const std::string extension = path.substr(pos);
    const auto it = mime_types.find(extension);

    if (it != mime_types.end()) {
        return it->second;
    }

    return "application/octet-stream";
}

std::string HttpsServerCoroutine::GetFileContent(const std::string& path) const
{
    std::ifstream file(path, std::ios::binary);

    if (!file.is_open()) {
        return {};
    }

    std::ostringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

std::optional<std::size_t> HttpsServerCoroutine::ExtractContentLength(const std::string& headers) const
{
    std::istringstream stream(headers);
    std::string line;

    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        const std::string prefix = "Content-Length:";

        if (line.size() >= prefix.size() &&
            std::equal(prefix.begin(), prefix.end(), line.begin(),
                [](char a, char b) {
                    return std::tolower(static_cast<unsigned char>(a)) ==
                           std::tolower(static_cast<unsigned char>(b));
                })) {

            std::string value = line.substr(prefix.size());
            value.erase(value.begin(), std::find_if(value.begin(), value.end(), [](unsigned char ch) {
                return !std::isspace(ch);
            }));

            try {
                return static_cast<std::size_t>(std::stoull(value));
            }
            catch (...) {
                return std::nullopt;
            }
        }
    }

    return std::nullopt;
}

bool HttpsServerCoroutine::IsHttpRequestComplete(const std::string& request) const
{
    const std::size_t headers_end = request.find("\r\n\r\n");

    if (headers_end == std::string::npos) {
        return false;
    }

    const std::string headers = request.substr(0, headers_end + 4);
    const std::optional<std::size_t> content_length = ExtractContentLength(headers);

    if (!content_length) {
        return true;
    }

    const std::size_t body_begin = headers_end + 4;
    const std::size_t body_size = request.size() > body_begin ? request.size() - body_begin : 0;

    return body_size >= *content_length;
}

void HttpsServerCoroutine::DoServiceWork()
{
    if (service_fun) {
        service_fun();
    }
}

void HttpsServerCoroutine::CleanupFinishedSessions()
{
    for (auto it = active_sessions_.begin(); it != active_sessions_.end(); ) {
        if (it->done()) {
            try {
                it->rethrow_if_exception();
            }
            catch (const std::exception& e) {
                std::cerr << "Client coroutine exception: " << e.what() << "\n";
            }
            catch (...) {
                std::cerr << "Client coroutine unknown exception\n";
            }

            it = active_sessions_.erase(it);
        }
        else {
            ++it;
        }
    }
}

void HttpsServerCoroutine::CloseSocket(SOCKET socket) noexcept
{
    if (socket != INVALID_SOCKET) {
        closesocket(socket);
    }
}

// ---------------- SQLite ----------------

HttpsServerCoroutine::Sqlite_::Sqlite_(std::string_view db_name, std::vector<std::string>& fields)
    : dbName(db_name), _fields(fields)
{
    int res = sqlite3_open(dbName.c_str(), &db);

    if (res != SQLITE_OK) {
        std::cerr << "Database opening error: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        db = nullptr;
        return;
    }

    std::cout << "Successfully opened the database: " << dbName << std::endl;

    std::string createTableSQL = R"(
        CREATE TABLE IF NOT EXISTS items (
        id INTEGER PRIMARY KEY AUTOINCREMENT);)";

    auto insert_name_field = [&](const std::string& text) {
        createTableSQL.insert(createTableSQL.length() - 2, ",\n\t" + text + " TEXT NOT NULL");
    };

    for (auto& field : _fields) {
        insert_name_field(field);
    }

    char* errMessage = nullptr;
    res = sqlite3_exec(db, createTableSQL.c_str(), nullptr, nullptr, &errMessage);

    if (res != SQLITE_OK) {
        std::cerr << "Error creating table: " << errMessage << std::endl;
        sqlite3_free(errMessage);
    }
    else {
        std::cout << "Table successfully created!" << std::endl;
    }

    sqlite3_close(db);
    db = nullptr;
}

HttpsServerCoroutine::Sqlite_::~Sqlite_()
{
    if (db) {
        sqlite3_close(db);
        db = nullptr;
    }
}

int HttpsServerCoroutine::Sqlite_::executeSQL(const std::string& sql, std::string& result)
{
    char* errMessage = nullptr;
    const int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errMessage);

    if (rc != SQLITE_OK) {
        result = "SQL Error: " + std::string(errMessage ? errMessage : "unknown");
        sqlite3_free(errMessage);
    }
    else {
        result = "Success";
    }

    return rc;
}

void HttpsServerCoroutine::Sqlite_::resetAutoIncrement(sqlite3* db_handle, const std::string& tableName)
{
    std::string resetSQL = "DELETE FROM sqlite_sequence WHERE name = '" + tableName + "';";
    char* errMessage = nullptr;
    const int rc = sqlite3_exec(db_handle, resetSQL.c_str(), nullptr, nullptr, &errMessage);

    if (rc != SQLITE_OK) {
        std::cerr << "Error resetting AUTOINCREMENT: " << errMessage << std::endl;
        sqlite3_free(errMessage);
    }
}

int HttpsServerCoroutine::Sqlite_::addItem(std::vector<std::string>& data_fields, std::string& response)
{
    sqlite3_open(dbName.c_str(), &db);

    if (!db) {
        response = "Database open error";
        return -1;
    }

    resetAutoIncrement(db, "items");

    std::string sql = "INSERT INTO items (";

    for (std::size_t i = 0; i < _fields.size(); ++i) {
        if (i < (_fields.size() - 1)) {
            sql.insert(sql.length(), _fields[i] + ", ");
        }
        else {
            sql.insert(sql.length(), _fields[i] + ")");
        }
    }

    sql.insert(sql.length(), " VALUES (");

    for (std::size_t i = 0; i < data_fields.size(); ++i) {
        if (i < (data_fields.size() - 1)) {
            sql.insert(sql.length(), "'" + data_fields[i] + "', ");
        }
        else {
            sql.insert(sql.length(), "'" + data_fields[i] + "');");
        }
    }

    executeSQL(sql, response);
    const int lastInsertId = static_cast<int>(sqlite3_last_insert_rowid(db));

    sqlite3_close(db);
    db = nullptr;

    return lastInsertId;
}

void HttpsServerCoroutine::Sqlite_::deleteItem(int id, std::string& response)
{
    sqlite3_open(dbName.c_str(), &db);

    if (!db) {
        response = "Database open error";
        return;
    }

    std::string sql = "DELETE FROM items WHERE id = " + std::to_string(id) + ";";
    executeSQL(sql, response);

    sqlite3_close(db);
    db = nullptr;
}

void HttpsServerCoroutine::Sqlite_::getItems(std::string& response)
{
    sqlite3_open(dbName.c_str(), &db);

    if (!db) {
        response = "Database open error";
        return;
    }

    const std::string sql = "SELECT * FROM items;";
    sqlite3_stmt* stmt = nullptr;

    const int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);

    if (rc != SQLITE_OK) {
        response = "Error preparing statement";
        sqlite3_close(db);
        db = nullptr;
        return;
    }

    Json::Value items(Json::arrayValue);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Json::Value item;
        item["id"] = sqlite3_column_int(stmt, 0);

        for (std::size_t i = 0; i < _fields.size(); ++i) {
            const unsigned char* text = sqlite3_column_text(stmt, static_cast<int>(i + 1));
            item[_fields[i]] = text ? std::string(reinterpret_cast<const char*>(text)) : "";
        }

        items.append(item);
    }

    Json::StreamWriterBuilder writer;
    response = Json::writeString(writer, items);

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    db = nullptr;
}
