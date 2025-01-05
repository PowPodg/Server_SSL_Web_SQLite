#include "serv/HttpsServer.h"
#include <fstream>
#include <sstream>
using namespace std;

int main(int ar, char**arg)
{
	std::string path_web_inerface = "web_interface/build";
	std::string base_name = "base_sql.db";
	vector <std::string> fields_base = { "name", "email" };

	HttpsServer srv("cert.pem", "key.pem", path_web_inerface, base_name, fields_base);
	srv.Use("GET",    "/api/items", nullptr);
	srv.Use("POST",   "/api/items", nullptr);
	srv.Use("DELETE", "/api/items/id", nullptr);

	srv.Listen(8120);

	return 0;
}
