#pragma once

#include <boost/asio.hpp>
#include <boost/json.hpp>
#include <pqxx/pqxx>
#include <iostream>
#include <string>
#include <memory>

class ServerKeyValue
{
	class PostgresBase {
	public:
		PostgresBase(const std::string& conn_str) : pool(std::make_unique<pqxx::connection>(conn_str)) {}
		
		bool is_connected() {
			if (pool && pool->is_open()) {
				return true;
			}
			return false;
		}

		std::optional<std::string> read(const std::string& key) {
			pqxx::work txn(*pool);
			pqxx::result res = txn.exec_params("SELECT value FROM storage WHERE key = $1", key);
			txn.commit();
			if (!res.empty()) {
				return res[0]["value"].as<std::string>();
			}
			return std::nullopt;
		}

		bool write(const std::string& key, const std::string& value) {
			pqxx::work txn(*pool);
			txn.exec_params("INSERT INTO storage (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", key, value);
			txn.commit();
			return true;
		}

	private:
		std::unique_ptr<pqxx::connection> pool;
	};

	std::unique_ptr<PostgresBase> db_postgr;
public:
	ServerKeyValue() = default;
	ServerKeyValue(const std::string&);
	~ServerKeyValue() { stop(); };
	bool Listen(const int& port);
	void stop() {
		running.store(false);
		if (acceptor) {
			if (!running.load())acceptor->close();
		}
		io_context.stop();
	}
private:
	boost::asio::awaitable<void> Execution_client(boost::asio::ip::tcp::socket socket);
	boost::asio::awaitable<void> Connect_waiting(const unsigned short&);
	boost::asio::io_context io_context;
	std::atomic<bool> running{ true };
	std::unique_ptr<boost::asio::ip::tcp::acceptor> acceptor;
};

