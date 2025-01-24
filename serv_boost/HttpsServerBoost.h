#pragma once

#ifdef _WIN32
#define _WIN32_WINNT 0x0A00
#else
//#include <unistd.h>
#endif

#include <filesystem>
#include <fstream>
#include <sstream>
#include <functional>
#include <unordered_map>
#include <iostream>
#include <mutex>
#include <string>
#include <list>
#include <vector>

#include <pqxx/pqxx>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ssl.hpp> 
#include <boost/json.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/sequenced_index.hpp>


class HttpsServBoost
{
	struct RestUrl {
		std::string method;
		std::string path;
	};
	static const int SIZE_STING = 255;
	static const int SIZE_GET_REQ = 4096;
	static const int MAX_QUANTITY_CONNECT = 32;//for 10k clients
	using VoidFun = std::function<void(const std::string&, std::string&)>;
	using arr_pairs = std::vector<std::pair<RestUrl, VoidFun>>;
	VoidFun void_func;
	arr_pairs arr_api_pairs;
	std::string path_web_inerface;
	std::string Data_received = std::string(SIZE_GET_REQ, '\0');
	std::string _resp = std::string(SIZE_GET_REQ, '\0');;
//------------------------------------------------------- 	   
	class DBConnectionPool {
	public:
		DBConnectionPool(size_t pool_size, const std::string& base_info) : base_info(base_info)
		{
			for (size_t i = 0; i < pool_size; ++i) {
				connections_.emplace_back(std::make_shared<pqxx::connection>(base_info));
			}
		}
		std::shared_ptr<pqxx::connection> get_connection() {
			std::lock_guard<std::mutex> lock(mutex_);
			if (!connections_.empty()) {
				auto conn = connections_.back();
				connections_.pop_back();
				return conn;
			}
			else {
				return std::make_shared<pqxx::connection>(base_info);
			}
		}
		void return_connection(std::shared_ptr<pqxx::connection> conn) {
			std::lock_guard<std::mutex> lock(mutex_);
			if (conn && conn->is_open()) {
				connections_.push_back(conn);
			}
			else {
				std::cerr << "Warning: Invalid connection returned to the pool\n";
			}
		}
	private:
		std::vector<std::shared_ptr<pqxx::connection>> connections_;
		std::mutex mutex_;
		std::string base_info;
	};

//-------------------------------------------------------
	std::shared_ptr<DBConnectionPool> db_pool;
	boost::asio::io_context io_context;
	std::unique_ptr<boost::asio::ssl::context> ssl_context;
	std::string base_config = std::string(SIZE_STING, '\0');
	const std::string STATIC_FILES_PATH = "./build";

	std::mutex connection_mutex;
	std::list<std::string> cache_order;
	const size_t MAX_CACHE_SIZE = 100;  
	const size_t MAX_CONNECTIONS = 1000; 

	std::mutex cache_mutex;
	struct CacheEntry {
		std::string file_path; 
		std::string content;   
		CacheEntry(const std::string& path, const std::string& data)
			: file_path(path), content(data) {
		}
	};

	using CacheContainer = boost::multi_index::multi_index_container<CacheEntry, boost::multi_index::indexed_by<
		boost::multi_index::ordered_unique<boost::multi_index::member<CacheEntry, std::string, &CacheEntry::file_path>>,
		boost::multi_index::sequenced<>>>;

	CacheContainer file_cache;

	std::string read_file(const std::string&);
	std::string get_cached_file(const std::string&);
	void add_to_cache(const std::string&, const std::string&);
	std::string get_mime_type(const std::string& file_path);

	boost::asio::awaitable<boost::json::object> execute_query(const std::string& query);
	
	size_t current_connections = 0;
	std::unique_ptr<boost::asio::thread_pool> thread_pool;

	void load_ssl_certificate(const std::string&, const std::string&);

	boost::asio::awaitable<void> Connect_waiting(const unsigned short&);
	boost::asio::awaitable<void> Execution(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>);
	boost::asio::awaitable<std::string> query_database(const std::string&);

public:
	HttpsServBoost() {};
	HttpsServBoost(const std::string&, const std::string&);
	HttpsServBoost(const std::string&, const std::string&, const std::string&);
	HttpsServBoost(const std::string&, const std::string&, const std::string&, const std::string&);

	bool Use(const std::string&, const std::string&, VoidFun);
	bool Listen(const int& port);

	~HttpsServBoost() { thread_pool->join(); };
};

