#include "ServerKeyValue.h"

ServerKeyValue::ServerKeyValue(const std::string& base_config)
{
	db_postgr = std::make_unique<PostgresBase>(base_config);
}
//----------------------------------------------------------------------
boost::asio::awaitable<void> ServerKeyValue::Execution_client(boost::asio::ip::tcp::socket socket)
{
	try {
		boost::asio::streambuf buffer;
		std::size_t n = co_await boost::asio::async_read_until(socket, buffer, "\0", boost::asio::use_awaitable);
		std::istream stream(&buffer);
		std::string request_str;
		std::getline(stream, request_str, '\0');

		std::cout << "Request received: " << request_str << "\n";

		boost::json::value req_json;
		boost::json::object response;

		try {
			req_json = boost::json::parse(request_str);

			if (!req_json.is_object()) {
				throw std::runtime_error("Invalid JSON format");
			}

			boost::json::object& req_obj = req_json.as_object();
			std::string request_type = req_obj["request"].as_string().c_str();
			std::string key = req_obj["key"].as_string().c_str();
			
			if (request_type == "read") {
				auto value = db_postgr->read(key);
				if (value) {
					response["status"] = "ok";
					response["value"] = *value;
				}
				else {
					response["status"] = "error";
					response["description"] = "Key not found";
				}
			}
			else if (request_type == "write") {
				if (req_obj.contains("value")) {
					std::string value = req_obj["value"].as_string().c_str();
					db_postgr->write(key, value);
					response["status"] = "ok";
				}
				else {
					response["status"] = "error";
					response["description"] = "Missing value field";
				}
			}
			else {
				response["status"] = "error";
				response["description"] = "Unknown request type";
			}
		}
		catch (const std::exception& e) {
			response["status"] = "error";
			response["description"] = e.what();
		}

		std::string response_str = boost::json::serialize(response) + "\n";
		co_await boost::asio::async_write(socket, boost::asio::buffer(response_str), boost::asio::use_awaitable);

		socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both);
		socket.close();
	}
	catch (const boost::system::system_error& e) {
		if (e.code() == boost::asio::error::eof) {
			std::cout << "The client closed the connection\n";
		}
		else {
			std::cerr << "Error: " << e.what() << "\n";
		}
	}
	catch (const std::exception& e) {
		std::cerr << "Unidentified error: " << e.what() << "\n";
	}
}
//-----------------------------------------------------------------------------------
boost::asio::awaitable<void> ServerKeyValue::Connect_waiting(const unsigned short& port)
{
	acceptor = std::make_unique<boost::asio::ip::tcp::acceptor>(io_context, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port));

	while (running.load()) {
		try {
			boost::asio::ip::tcp::socket socket = co_await acceptor->async_accept(boost::asio::use_awaitable);
			std::cout << "New connection accepted!" << std::endl;
			boost::asio::co_spawn(acceptor->get_executor(), Execution_client(std::move(socket)), boost::asio::detached);
		}
		catch (const boost::system::system_error& e) {
			if (e.code() == boost::asio::error::operation_aborted) {
				std::cerr << "The accept operation was aborted (likely due to server stop)." << std::endl;
			}
			else {
				std::cerr << "Other error: " << e.what() << std::endl;
			}
			std::cerr << "Critical error accepting connection: " << e.what() << std::endl;
			running.store(false); 
		}
	}
}
//-------------------------------------------------------------------
bool ServerKeyValue::Listen(const int& port)
{
	try
	{
		boost::asio::co_spawn(io_context, Connect_waiting(port), boost::asio::detached);
		io_context.run();
	}
	catch (const std::exception& e)
	{
		std::cerr << "Error in Listen: " << e.what() << std::endl;
		return false;
	}
}
