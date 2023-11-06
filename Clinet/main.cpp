#include "Client.h"

int main() {
	Client* c = new Client;
	int failure_flag;
	int tries;


	std::cout << "Starting transfer" << std::endl;
	if (std::filesystem::exists("me.info"))
	{
		for (tries = 1; tries < 4; tries++)
		{
			failure_flag = c->request(RECONNECT);
			if (failure_flag)
			{	
				if (tries == 3)
				{
					std::cout << "Reconnect rejected, restart again as new client." << std::endl;
					return 1;
				}
				std::cout << "Server responded with an error" << std::endl;
			}
			else break;
		}
		std::cout << "Reconnected" << std::endl;
	}
	else
	{
		for (tries = 1; tries < 4; tries++)
		{
			failure_flag = c->request(REGISTER);
			if (failure_flag)
			{
				if (tries == 3) 
				{
					std::cout << "Registry proccess failed, exiting program." << std::endl;
					return 1;
				}
				std::cout << "Server responded with an error" << std::endl;
			}
			else break;
		}
		
		std::cout << "Registered" << std::endl;

		for (tries = 1; tries < 4; tries++)
		{
			failure_flag = c->request(CONNECT);
			if (failure_flag)
			{
				if (tries == 3) return 1;
				std::cout << "Server responded with an error" << std::endl;
			}
			else break;
		}
		std::cout << "Connected" << std::endl;
	}

	
	for (tries = 0; tries < 4; tries++)
	{
		std::cout << "Sending file: " << get_file_path() << std::endl;
		failure_flag = c->request(SEND);
		if (failure_flag)
		{
			c->request(INVALID_CRC);
			std::cout << "File transfer failed" << std::endl;
		}
		else
		{
			
			c->request(VALID_CRC);
			std::cout << "Checksum test passed, end communication" << std::endl;
			break;
		}
	}

	if (tries == 4) 
	{
		c->request(FINAL_INVALID_CRC);
	}


	return 0;
}