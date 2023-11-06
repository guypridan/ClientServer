#include "Client.h"


int Client::request(uint16_t req_code)
{
    // Create a socket
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "Error creating socket: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    // Connect to the server
    if (connect(clientSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
        std::cerr << "Error connecting to server: " << WSAGetLastError() << std::endl;
        return 1;
    }
    

    switch (req_code) {
    case REGISTER:
        return register_req();
    case CONNECT:
    case RECONNECT:
        return connect_req(req_code%2);
    case SEND:
        return send_req();
    }
    return filename_payload_req(req_code);
}

int Client::register_req()
{
    pack_header(buffer, cid, VERSION, REGISTER, NAME_SIZE);

    // pack payload
    std::memcpy(buffer + REQ_HEADER_SIZE, name.c_str(), name.length());

    // send register request
    int bytesSent = send(clientSocket, buffer, MSG_SIZE, 0);
    clean_buffer(buffer);

    // recieve response from server
    recv(clientSocket, buffer, MSG_SIZE, 0);

    // check for registration success
    uint16_t res_code = unpack_code(&buffer[RES_CODE_OFFSET]);
    if (res_code == REG_FAILED)
    {
        std::cerr << "User registration failed." << std::endl;
        return 1;
    }
    else if (res_code != REG_SUCCESS)
    {
        std::cerr << "Unexpected response code." << std::endl;
        return 1;
    }

    // unpack client id from payload
    unpack_bytes(cid, &buffer[RES_HEADER_SIZE], CID_SIZE);

    // create me.info
    std::ofstream me("me.info");
    if (!me.is_open())
    {
        std::cerr << "Failed to open me.info for writing." << std::endl;
        return 1;
    }
    
    // write data to me.info
    // user name
    me << name << std::endl;
    
    // write client id in a hexa representation
    std::ios::fmtflags f(me.flags());
    me << std::hex << std::setfill('0');
    for (size_t i = 0; i < CID_SIZE; i++)
        me << std::setw(2) << (0xFF & cid[i]);
    me << std::endl;
    me.flags(f);

    // write public key encoded to base 64
    me << Base64Wrapper::encode(rsaWrap->getPublicKey());
    me.close();

    // write priv.key
    std::ofstream priv("priv.key");
    if (!priv.is_open())
    {
        std::cerr << "Failed to open priv.key for writing." << std::endl;
        return 1;
    }
    priv << Base64Wrapper::encode(rsaWrap->getPrivateKey());
    priv.close();
    clean_buffer(buffer);

    return 0;
}

int Client::connect_req(int reconnect_flag)
{

    
    // pack response header
    uint32_t payload_size = reconnect_flag ? NAME_SIZE : NAME_SIZE + RSAPublicWrapper::KEYSIZE;
    pack_header(buffer, cid, VERSION, CONNECT + reconnect_flag, payload_size);

    // pack payload
    std::memcpy(buffer + REQ_HEADER_SIZE, name.c_str(), name.length());
    if (!reconnect_flag)
    {
        std::memcpy(buffer + REQ_HEADER_SIZE + NAME_SIZE, rsaWrap->getPublicKey().c_str(), RSAPublicWrapper::KEYSIZE);
    }

    // send response
    send(clientSocket, buffer, MSG_SIZE, 0);
    clean_buffer(buffer);
    
    // recieve response
    recv(clientSocket, buffer, MSG_SIZE, 0);

    uint16_t res_code = unpack_code(&buffer[RES_CODE_OFFSET]);

    
    if (res_code != RSA_RECIEVED && res_code != RECONNECT_ACCEPTED) {
        std::cerr << "Unexpected response code." << std::endl;
        return 1;
    }

    // unpack aes key
    payload_size = get_payload_size(&buffer[RES_PAYLOAD_SIZE_OFFSET]);
    uint32_t encrypted_aes_size = payload_size - CID_SIZE;
    char* aes_encrypted_data = new char[encrypted_aes_size];
    unpack_bytes(aes_encrypted_data, &buffer[RES_HEADER_SIZE + CID_SIZE], encrypted_aes_size);

    // decrypt key
    aes_key = rsaWrap->decrypt(aes_encrypted_data, encrypted_aes_size);
    valid_aes_key = true;

    clean_buffer(buffer);
    delete[] aes_encrypted_data;

    return 0;
}

int Client::send_req()
{
    // read file path from transfor.info and encrypt its data
    std::string source_f = get_file_path();
    std::string encrypted_file = encrypt_file(source_f, aes_key);
    
    // prompt the server to expect a file transfer
    // pack header
    uint32_t encrypted_file_size = static_cast<uint32_t>(encrypted_file.size());
    uint32_t payload_size = encrypted_file_size + NAME_SIZE + sizeof(uint32_t);
    pack_header(buffer, cid, VERSION, SEND, payload_size);

    // pack payload
    char* cp = &buffer[REQ_HEADER_SIZE];
    std::memcpy(cp, &encrypted_file_size, sizeof(uint32_t));
    cp += sizeof(uint32_t);
    std::memcpy(cp, source_f.c_str(), source_f.length());

    // send request for file upload
    send(clientSocket, buffer, MSG_SIZE, 0);
    clean_buffer(buffer);


    // send encrypted data
    const char* fbuffer = encrypted_file.c_str();
    unsigned int i = 0;
    while (i < encrypted_file_size)
    {
        std::memcpy(buffer, &fbuffer[i], MSG_SIZE);
        i += MSG_SIZE;
        send(clientSocket, buffer, MSG_SIZE, 0);
    }

    // receive response
    recv(clientSocket, buffer, MSG_SIZE, 0);
    uint16_t res_code = unpack_code(&buffer[RES_CODE_OFFSET]);
    uint32_t server_cksum = 0;
    std::memcpy(&server_cksum, &buffer[RES_CRC_OFFSET], sizeof(uint32_t));

    // test if crc result of server matches own
    if (res_code == CRC_CHECK && cksum(source_f) == server_cksum)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

int Client::filename_payload_req(uint16_t req_code)
{
    pack_header(buffer, cid, VERSION, req_code, NAME_SIZE);

    // pack filename
    std::string source_f = get_file_path();
    std::memcpy(&buffer[REQ_HEADER_SIZE], source_f.c_str(), source_f.size());
    send(clientSocket, buffer, MSG_SIZE, 0);
    return 0;
}