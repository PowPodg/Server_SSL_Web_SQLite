#pragma once

#ifdef _WIN32
#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
using SOCKET = int;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR   (-1)
#include <cerrno>
#include <fcntl.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
inline int WSACleanup() { return 0; }
inline int closesocket(SOCKET sock) { return close(sock); }
using ADDRINFO = struct addrinfo;
#define WSAGetLastError() (errno)
#endif

#include <coroutine>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <queue>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "sqlite/sqlite3.h"
#include "json/json/json.h"

class HttpsServerCoroutine
{
private:
    struct RestUrl {
        std::string method;
        std::string path;
    };

    static constexpr int SIZE_GET_REQ = 4096;
    static constexpr std::size_t MAX_HTTP_REQUEST_SIZE = 1024 * 1024;

public:
    using VoidFun = std::function<void(const std::string&, std::string&)>;
    using ServiceFun = std::function<void()>;

private:
    using arr_pairs = std::vector<std::pair<RestUrl, VoidFun>>;

    class Task
    {
    public:
        struct promise_type
        {
            Task get_return_object() noexcept
            {
                return Task{ std::coroutine_handle<promise_type>::from_promise(*this) };
            }

            std::suspend_always initial_suspend() noexcept { return {}; }
            std::suspend_always final_suspend() noexcept { return {}; }
            void return_void() noexcept {}

            void unhandled_exception()
            {
                exception = std::current_exception();
            }

            std::exception_ptr exception;
        };

        Task() noexcept = default;

        explicit Task(std::coroutine_handle<promise_type> handle) noexcept
            : handle_(handle)
        {}

        Task(Task&& other) noexcept
            : handle_(std::exchange(other.handle_, {}))
        {}

        Task& operator=(Task&& other) noexcept
        {
            if (this != &other) {
                destroy();
                handle_ = std::exchange(other.handle_, {});
            }
            return *this;
        }

        Task(const Task&) = delete;
        Task& operator=(const Task&) = delete;

        ~Task()
        {
            destroy();
        }

        void start()
        {
            if (handle_ && !handle_.done()) {
                handle_.resume();
            }
        }

        bool done() const
        {
            return !handle_ || handle_.done();
        }

        void rethrow_if_exception()
        {
            if (handle_ && handle_.promise().exception) {
                std::rethrow_exception(handle_.promise().exception);
            }
        }

    private:
        void destroy() noexcept
        {
            if (handle_) {
                handle_.destroy();
                handle_ = {};
            }
        }

        std::coroutine_handle<promise_type> handle_{};
    };

    class Scheduler
    {
    public:
        void schedule(std::coroutine_handle<> handle);
        void wait_read(SOCKET socket, std::coroutine_handle<> handle);
        void wait_write(SOCKET socket, std::coroutine_handle<> handle);

        void run_ready();
        void poll_io(int timeout_ms);
        bool has_work() const;

    private:
        std::queue<std::coroutine_handle<>> ready_;
        std::unordered_map<SOCKET, std::coroutine_handle<>> read_waiters_;
        std::unordered_map<SOCKET, std::coroutine_handle<>> write_waiters_;
    };

    class WaitRead
    {
    public:
        WaitRead(Scheduler& scheduler, SOCKET socket) noexcept
            : scheduler_(scheduler), socket_(socket)
        {}

        bool await_ready() const noexcept { return false; }
        void await_suspend(std::coroutine_handle<> handle) noexcept;
        void await_resume() const noexcept {}

    private:
        Scheduler& scheduler_;
        SOCKET socket_;
    };

    class WaitWrite
    {
    public:
        WaitWrite(Scheduler& scheduler, SOCKET socket) noexcept
            : scheduler_(scheduler), socket_(socket)
        {}

        bool await_ready() const noexcept { return false; }
        void await_suspend(std::coroutine_handle<> handle) noexcept;
        void await_resume() const noexcept {}

    private:
        Scheduler& scheduler_;
        SOCKET socket_;
    };

    class YieldToServer
    {
    public:
        explicit YieldToServer(Scheduler& scheduler) noexcept
            : scheduler_(scheduler)
        {}

        bool await_ready() const noexcept { return false; }
        void await_suspend(std::coroutine_handle<> handle) noexcept;
        void await_resume() const noexcept {}

    private:
        Scheduler& scheduler_;
    };

public:
    class Sqlite_
    {
    public:
        explicit Sqlite_(std::string_view db_name, std::vector<std::string>& fields);
        ~Sqlite_();

        int executeSQL(const std::string& sql, std::string& result);
        int addItem(std::vector<std::string>& data_fields, std::string& response);
        void deleteItem(int id, std::string& response);
        void getItems(std::string& response);
        void resetAutoIncrement(sqlite3* db, const std::string& tableName);

        std::vector<std::string> _fields;

    private:
        sqlite3* db = nullptr;
        std::string dbName;
    };

public:
    HttpsServerCoroutine(std::string_view cert, std::string_view private_key);
    HttpsServerCoroutine(std::string_view cert, std::string_view private_key, std::string_view path_web);
    HttpsServerCoroutine(
        std::string_view cert,
        std::string_view private_key,
        std::string_view path_web,
        std::string_view name_bd,
        std::vector<std::string>& fields
    );

    ~HttpsServerCoroutine();

    bool Use(const std::string& method, const std::string& path, VoidFun f);
    void SetServiceFunction(ServiceFun f);
    bool Listen(const int& port);
    void Stop();

private:
    SOCKET Create_listen_socket(const int& port);
    void TryAcceptClients();
    Task HandleClient(SOCKET client_sock);

    bool SetSocketBlocking(SOCKET socket, bool blocking);
    bool IsWouldBlock() const;

    std::optional<std::string> BuildResponseFromRequest(const std::string& request);
    std::string HandleGet(const std::string& request, const std::string& path);
    std::string HandlePost(const std::string& request, const std::string& path, const std::string& body);
    std::string HandleDelete(const std::string& request, const std::string& path);

    std::string MakeHttpResponse(
        const std::string& status,
        const std::string& content_type,
        const std::string& body
    ) const;

    std::string GetMimeType(const std::string& path) const;
    std::string GetFileContent(const std::string& path) const;
    std::optional<std::size_t> ExtractContentLength(const std::string& headers) const;
    bool IsHttpRequestComplete(const std::string& request) const;

    void DoServiceWork();
    void CleanupFinishedSessions();
    void CloseSocket(SOCKET socket) noexcept;

private:
    arr_pairs arr_api_pairs;
    std::unique_ptr<Sqlite_> bd_sqlite;

    SSL_CTX* ssl_ctx = nullptr;
    SOCKET listen_sock = INVALID_SOCKET;

    Scheduler scheduler_;
    std::list<Task> active_sessions_;

    std::string path_web;
    ServiceFun service_fun;
    bool running = false;
};
