#include "ServerKeyValue/ServerKeyValue.h"

int main()
{
	try
	{
		std::string base_config = std::string("postgresql://postgres:123@localhost:8121/test");
		ServerKeyValue srv(base_config);
		srv.Listen(8120);
	}
	catch (const std::exception& e)
	{
		std::cerr << "Server error: " << e.what() << "\n";
	}
	return 0;
}