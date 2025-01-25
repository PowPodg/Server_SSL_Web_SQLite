#include "HttpsServerBoost.h"

HttpsServBoost::HttpsServBoost(const std::string& cert, const std::string& key)
{
	thread_pool = std::make_unique<boost::asio::thread_pool>(std::thread::hardware_concurrency());
	ssl_context = std::make_unique<boost::asio::ssl::context>(boost::asio::ssl::context::tlsv12_server);
	boost::asio::ssl::context ssl_context(boost::asio::ssl::context::tlsv12_server);
	load_ssl_certificate(cert, key);
}
//------------------------------------------------------------
HttpsServBoost::HttpsServBoost(const std::string& cert, const std::string& key, const std::string& path_web_inerf)
	:HttpsServBoost::HttpsServBoost(cert, key)
{
	path_web_inerface = std::string(path_web_inerf);
}
//----------------------------------------------------------------------------------------------
HttpsServBoost::HttpsServBoost(const std::string& cert, const std::string& key, const std::string& path_web_inerf, const std::string& base_config)
	:HttpsServBoost::HttpsServBoost(cert, key, path_web_inerf)
{
	db_pool = std::make_shared<DBConnectionPool>(MAX_QUANTITY_CONNECT, base_config);
}
//--------------------------------------------------------------------------------------
boost::asio::awaitable<void> HttpsServBoost::Connect_waiting(const unsigned short& port)
{
	boost::asio::ip::tcp::acceptor acceptor(io_context, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port));
	acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));

	while (true) {
		boost::asio::ip::tcp::socket socket(io_context);
		std::cout << "Waiting for connection..." << std::endl;

		boost::system::error_code ec;
		co_await acceptor.async_accept(socket, boost::asio::use_awaitable);
		if (ec) {
			std::cerr << "Error during async_accept: " << ec.message() << std::endl;
			continue;
		}
		boost::asio::ssl::stream<boost::asio::ip::tcp::socket> client_sock(std::move(socket), *ssl_context);
		boost::asio::co_spawn(
			*thread_pool,
			Execution(std::move(client_sock)),
			boost::asio::detached
		);
	}
}
//------------------------------------------------------------
bool HttpsServBoost::Use(const std::string& method, const std::string& path, VoidFun f)
{
	RestUrl data_rest;
	data_rest.method = method;
	data_rest.path = path;
	arr_api_pairs.emplace_back(data_rest, std::move(f));
	return true;
}
//----------------------------------------------------
bool HttpsServBoost::Listen(const int& port)
{
	try {
		boost::asio::co_spawn(io_context, Connect_waiting(port), boost::asio::detached);

		std::vector<std::jthread> threads;
		for (size_t i = 0; i < std::thread::hardware_concurrency(); ++i) {
			threads.emplace_back([&] { io_context.run(); });
		}
	}
	catch (const std::exception& e) {
		std::cerr << "Error in Listen: " << e.what() << std::endl;
		return false;
	}
	return true;
}
//------------------------------------------------------------
std::string HttpsServBoost::read_file(const std::string& file_path)
{
	std::ifstream file(file_path, std::ios::binary);
	if (!file.is_open()) {
		throw std::runtime_error("File not found: " + file_path);
	}
	std::ostringstream ss;
	ss << file.rdbuf();
	return ss.str();
}
//------------------------------------------------------------------------------------
std::string HttpsServBoost::get_cached_file(const std::string& file_path)
{
	{
		std::lock_guard<std::mutex> lock(cache_mutex);
		auto& ordered_index = file_cache.get<0>(); 
		auto it = ordered_index.find(file_path);
		if (it != ordered_index.end()) {
			file_cache.get<1>().relocate(file_cache.get<1>().begin(), file_cache.project<1>(it));
			return it->content;
		}
	}
	std::string content = read_file(file_path);
	add_to_cache(file_path, content);
	return content;
}
//---------------------------------------------------------------------------------------
void HttpsServBoost::add_to_cache(const std::string& file_path, const std::string& content)
{
	std::lock_guard<std::mutex> lock(cache_mutex);
	auto& ordered_index = file_cache.get<0>(); 
	auto it = ordered_index.find(file_path);
	if (it != ordered_index.end()) {
		file_cache.get<1>().relocate(file_cache.get<1>().begin(), file_cache.project<1>(it));
		return;
	}
	if (file_cache.size() >= MAX_CACHE_SIZE) {
		file_cache.get<1>().pop_back();
	}
	file_cache.emplace(file_path, content);
}
//-------------------------------------------------------------------
std::string HttpsServBoost::get_mime_type(const std::string& path)
{
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
//----------------------------------------------------------------------
boost::asio::awaitable<boost::json::object> HttpsServBoost::execute_query(const std::string& query)
{
	std::shared_ptr<pqxx::connection> conn = nullptr;
	try {
		conn = db_pool->get_connection();
		pqxx::work txn(*conn); 
		pqxx::result res = txn.exec(query); 
		boost::json::object json_result;
		if (!res.empty()) {
			const auto& row = res[0]; 
    		json_result["id"] = row["id"].as<int>(); 
			json_result["name"] = row["name"].c_str();
			json_result["email"] = row["email"].c_str();
		}
		txn.commit();
		db_pool->return_connection(conn);
		co_return json_result;
	}
	catch (const std::exception& e) {
		std::cerr << "Ошибка базы данных: " << e.what() << std::endl;
		if (conn) {
			db_pool->return_connection(conn);
		}
		throw;
	}
}
//-----------------------------------------------------------------------------------------------------
void HttpsServBoost::load_ssl_certificate(const std::string& cert, const std::string& key)
{
	try {
		ssl_context->set_options(
			boost::asio::ssl::context::default_workarounds |
			boost::asio::ssl::context::no_sslv2 |
			boost::asio::ssl::context::no_sslv3 |
			boost::asio::ssl::context::single_dh_use
		);
		ssl_context->use_certificate_chain_file("cert.pem");
		ssl_context->use_private_key_file("key.pem", boost::asio::ssl::context::pem);
	}
	catch (const std::exception& e) {
		std::cerr << "Error loading SSL certificates: " << e.what() << std::endl;
	}
}
//----------------------------------------------------------------------------------------------
boost::asio::awaitable<void> HttpsServBoost::Execution(boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket)
{
	try {
		{
			std::lock_guard<std::mutex> lock(connection_mutex);
			if (current_connections >= MAX_CONNECTIONS) {
				socket.lowest_layer().close();
				co_return;
			}
			++current_connections;
		}

		co_await socket.async_handshake(boost::asio::ssl::stream_base::server, boost::asio::use_awaitable);

		boost::beast::flat_buffer buffer;
		boost::beast::http::request<boost::beast::http::string_body> req;
		co_await boost::beast::http::async_read(socket, buffer, req, boost::asio::use_awaitable);

		boost::beast::http::response<boost::beast::http::string_body> res;
		res.version(req.version());
		res.set(boost::beast::http::field::server, "Boost.Beast/1.0");

		std::cout << "Received request: " << req.method_string() << " " << req.target() << std::endl;

		auto resp_not_found = [&]() {
			res.result(boost::beast::http::status::not_found);
			res.set(boost::beast::http::field::content_type, "text/plain");
			res.body() = "404 Not Found";
			};

		auto bad_req = [&]() {
			res.result(boost::beast::http::status::bad_request);
			res.set(boost::beast::http::field::content_type, "text/plain");
			res.body() = "Method not allowed";
			};

		try {
			std::string target = std::string(req.target());
			if (target == "/") {
				target = "/index.html";
			}

			for (std::pair<RestUrl, VoidFun>& p : arr_api_pairs)
			{
				if (req.method() == boost::beast::http::verb::get && p.first.method == "GET") {
					if (p.second) {
						if (target == p.first.path) {
							void_func = p.second;
							void_func(Data_received, _resp);
							res.result(boost::beast::http::status::ok);
							res.set(boost::beast::http::field::content_type, "application/json");
							res.body() = _resp;
						}
						else resp_not_found();
					}
					else
					{
						if (target == p.first.path) {
							if (db_pool) {
								std::string result = co_await query_database("SELECT id, name, email FROM users");// ("SELECT id, name, email FROM users");
								res.result(boost::beast::http::status::ok);
								res.set(boost::beast::http::field::content_type, "application/json");
								res.body() = result;
							}
							else {
								bad_req();
							}
						}
						else {
							std::string file_path = path_web_inerface + target;
							if (!std::filesystem::exists(file_path) || !std::filesystem::is_regular_file(file_path)) {
								throw std::runtime_error("File not found");
							}
							std::string file_content = get_cached_file(file_path);
							res.result(boost::beast::http::status::ok);
							res.set(boost::beast::http::field::content_type, get_mime_type(file_path));
							res.body() = file_content;
						}
					}
				}
				else if (req.method() == boost::beast::http::verb::post && p.first.method == "POST") {
					boost::json::value json_body = boost::json::parse(req.body());
					boost::json::object json_obj = json_body.as_object();
					std::string name = json_obj.at("name").as_string().c_str();
					std::string email = json_obj.at("email").as_string().c_str();
					if (name.empty() || email.empty()) {
						throw std::invalid_argument("Both 'name' and 'email' must be provided.");
					}

					std::string insert_query = "INSERT INTO users (name, email) VALUES ('" + name + "', '" + email + "') RETURNING id, name, email";
					if (db_pool) {
						boost::json::object  result_json = co_await execute_query(insert_query); 
						res.result(boost::beast::http::status::created);
						res.set(boost::beast::http::field::content_type, "application/json");
						res.body() = boost::json::serialize(result_json); 
					}
					else {
						bad_req();
					}
				}
				else if (req.method() == boost::beast::http::verb::delete_ && target.starts_with("/api/items/id/") && p.first.method == "DELETE")
				{
					std::string id = target.substr(target.find_last_of("/") + 1);  
					std::string delete_query = "DELETE FROM users WHERE id = " + id;
					if (db_pool) {
						co_await execute_query(delete_query); 
						res.result(boost::beast::http::status::ok);
						res.set(boost::beast::http::field::content_type, "application/json");
						res.body() = "{\"status\": \"deleted\"}";
					}
					else {
						bad_req();
					}
				}
				else {
					continue;
				}
			}
		}
		catch (const std::exception& e) {
			std::cerr << "Error processing request: " << e.what() << std::endl;
			resp_not_found();
		}
		co_await boost::beast::http::async_write(socket, res, boost::asio::use_awaitable);
	}
	catch (const std::exception& e) {
		std::cerr << "Error in handle_client: " << e.what() << std::endl;
	}

	try {
		socket.shutdown();
		socket.lowest_layer().close();
	}
	catch (const std::exception& e) {
		std::cerr << "Error closing connection: " << e.what() << std::endl;
	}

	{
		std::lock_guard<std::mutex> lock(connection_mutex);
		--current_connections;
	}
}
//--------------------------------------------------------------------------------------------
boost::asio::awaitable<std::string> HttpsServBoost::query_database(const std::string& query) {
	std::shared_ptr<pqxx::connection> conn = nullptr;
	try {
		conn = db_pool->get_connection();
		pqxx::work txn(*conn);
		pqxx::result res = txn.exec(query);
		boost::json::array json_result;
		
		for (const auto& row : res) {
			boost::json::object json_row;
			json_row["id"] = row[0].as<int>(); 
			if (row[1].is_null()) {
				json_row["name"] = "";
			}
			else {
				json_row["name"] = row[1].c_str();
			}

			if (row[2].is_null()) {
				json_row["email"] = ""; 
			}
			else {
				json_row["email"] = row[2].c_str();
			}
			json_result.push_back(json_row);
		}

		txn.commit();
		db_pool->return_connection(conn);
		co_return boost::json::serialize(json_result);
	}
	catch (const std::exception& e) {
		std::cerr << "Ошибка базы данных: " << e.what() << std::endl;
		if (conn) {
			db_pool->return_connection(conn);
		}
		boost::json::object error_response;
		error_response["error"] = e.what();
		co_return boost::json::serialize(error_response);
	}
}
