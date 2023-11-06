#include "PackUtil.h"
 
void pack_header(char* buffer, char* ClientID, uint8_t cli_version, uint16_t reqCode, uint32_t payloadSize)
{
	char* p = buffer;

	if (reqCode != REGISTER) {memcpy(p, ClientID, CID_SIZE);}
	p += CID_SIZE;

	memcpy(p, &cli_version, sizeof(cli_version));
	p += sizeof(cli_version);

	memcpy(p, &reqCode, sizeof(reqCode));
	p += sizeof(reqCode);

	memcpy(p, &payloadSize, sizeof(payloadSize));
}

void clean_buffer(char* buffer)
{
	std::memset(buffer, 0, MSG_SIZE);
}

uint16_t unpack_code(char* code)
{
	uint8_t b1 = code[0];
	uint8_t b2 = code[1];

	return (b2 << 8) | b1;
}

void unpack_bytes(char* dest, char* src, unsigned int len)
{
	for (unsigned int i = 0; i < len; i++) {
		dest[i] = src[i];
	}
}

uint32_t get_payload_size(char* buffer)
{
	uint32_t result = 0;
	for (int i = 0; i < 4; i++) {
		result |= ((uint32_t)buffer[i] & 0xFF) << (8 * i);
	}
	return result;
}

std::string get_file_path()
{
	std::string source_path;

	// get source file path
	std::ifstream transfer("transfer.info");
	if (!transfer.is_open())
	{
		std::cerr << "Couldn't find transfer.info" << std::endl;
		exit(1);
	}
	std::getline(transfer, source_path);
	std::getline(transfer, source_path);
	std::getline(transfer, source_path);
	transfer.close();

	return source_path;
}

std::string encrypt_file(std::string s_path, std::string aes_key)
{

	// open plain file
	std::ifstream plain_file(s_path, std::ios::binary);
	if (!plain_file.is_open())
	{
		std::cerr << "Couldn't open " << s_path << std::endl;
		exit(1);
	}

	// read file to buffer
	size_t size = std::filesystem::file_size(s_path);
	char* fbuffer = new char[size];
	plain_file.seekg(0, std::ios::beg);
	plain_file.read(fbuffer, size);
	
	// encrypt data
	AESWrapper aes(reinterpret_cast<const unsigned char*>(aes_key.c_str()), AESWrapper::DEFAULT_KEYLENGTH);
	std::string encrypted_data = aes.encrypt(fbuffer, static_cast<unsigned int>(size));

	return encrypted_data;
}
