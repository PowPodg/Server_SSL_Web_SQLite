#define CATCH_CONFIG_RUNNER  
#include <catch2/catch_all.hpp> 
#include <boost/asio.hpp>
#include <boost/json.hpp>
#include <boost/asio/streambuf.hpp>
#include <iostream>
#include <string>
#include "../ServerKeyValue/ServerKeyValue.h"
#include <thread>

std::string base_config = std::string("postgresql://postgres:123@localhost:8121/test");

std::string send_request(const std::string& request_json) {
	using namespace boost::asio;
	io_context io;
	ip::tcp::socket socket(io);
	socket.connect(ip::tcp::endpoint(ip::make_address("127.0.0.1"), 8120));

	write(socket, buffer(request_json + "\0"));

	boost::asio::streambuf response;
	read_until(socket, response, "\0");

	std::istream stream(&response);
	std::string response_str;
	std::getline(stream, response_str, '\0');

	return response_str;
}

TEST_CASE("DATABASE PostgeSQL CONNECTION", "[database]") {
	ServerKeyValue srv(base_config);  
	REQUIRE_NOTHROW(srv);  
}

TEST_CASE("WRITE DATA", "[integration]") {
	std::string response = send_request(R"({"request": "write", "key": "key1", "value": "y"})");
	boost::json::value expected = boost::json::parse(R"({"status": "ok"})");
	boost::json::value actual = boost::json::parse(response);
	REQUIRE(actual == expected);
}

TEST_CASE("READ DATA", "[integration]") {
	std::string response = send_request(R"({"request": "read", "key": "key1"})");
	boost::json::value expected = boost::json::parse(R"({"status": "ok", "value": "y"})");
	boost::json::value actual = boost::json::parse(response);
	REQUIRE(actual == expected);
}

int main(int argc, char* argv[]) {
	std::setlocale(LC_ALL, "en_US.UTF-8");
	ServerKeyValue srv(base_config);
	std::jthread server_thread([&]() {
		srv.Listen(8120);
		});
	std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	int result = Catch::Session().run(argc, argv);

	srv.stop();

	server_thread.request_stop(); 
	if (server_thread.joinable()) server_thread.join();

	std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	return result;
}