#pragma once
#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>
#include <WinSock2.h>
#include <Windows.h>
#include <ws2tcpip.h>
#include <tchar.h>
#include <cstdint>
#include <string>

#include "PackUtil.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include "Base64Wrapper.h"
#include "cksum.h"

#pragma comment(lib, "ws2_32.lib")

#define VERSION 3

// format
#define MSG_SIZE 1024
#define NAME_SIZE 255
#define CID_SIZE 16

#define REQ_HEADER_SIZE 23

#define RES_HEADER_SIZE 7
#define RES_CODE_OFFSET 1
#define RES_PAYLOAD_SIZE_OFFSET 3
#define RES_CRC_OFFSET 282

// request codes
#define REGISTER 1025
#define CONNECT 1026
#define RECONNECT 1027
#define SEND 1028
#define VALID_CRC 1029
#define INVALID_CRC 1030
#define FINAL_INVALID_CRC 1031

// response codes
#define REG_SUCCESS 2100
#define REG_FAILED 2101
#define RSA_RECIEVED 2102
#define CRC_CHECK 2103
#define MSG_RECEIVED 2104
#define RECONNECT_ACCEPTED 2105
#define RECONNECT_DENIED 2106
#define GENERAL_SERVER_ERR 2107


class Client
{
    // socket
    sockaddr_in serverAddress;
    SOCKET clientSocket;

    // encryption
    RSAPrivateWrapper* rsaWrap;
    char aesBuffer[AESWrapper::DEFAULT_KEYLENGTH];
    std::string aes_key;
    bool valid_aes_key = false;

    // server
    const char* ip = "127.0.0.1";
    const int port = 1996;
    
    // client
    char buffer[MSG_SIZE] = { 0 };
    std::string name;
    char cid[CID_SIZE] = { 0 };


public:
    Client()
    {
        // Initialize Winsock
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            std::cerr << "Failed to initialize Winsock" << std::endl;
            exit(1);
        }

        // Define the server address and port
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_port = htons(static_cast<u_short>(port));
        inet_pton(AF_INET, ip, &serverAddress.sin_addr.s_addr);

        if (std::filesystem::exists("me.info"))
        {
            // open me.info
            std::ifstream me("me.info");
            if (!me.is_open())
            {
                std::cerr << "could not open me.info" << std::endl;
                exit(1);
            }
            
            // read username line
            std::getline(me, name);

            // reload cid
            std::string line;
            std::getline(me, line);

            // translate client id
            for (int i = 0; i < CID_SIZE; i++)
            {
                std::string byteStr = line.substr(i * 2, 2);
                cid[i] = (char)strtol(byteStr.c_str(), NULL, 16);
            }
            me.close();

            // get rsa private key
            std::ifstream priv_key("priv.key");
            if (!priv_key.is_open())
            {
                std::cerr << "could not open priv.key" << std::endl;
                exit(1);
            }
            std::string key = "";
            while (!priv_key.eof())
            {
                std::getline(priv_key, line);
                key.append(line);
            }
            priv_key.close();

            // create rsaWrapper
            rsaWrap = new RSAPrivateWrapper(Base64Wrapper::decode(key));

        }
        else
        {
            // read username from transfer.info
            std::ifstream transfer("transfer.info");
            if (!transfer.is_open())
            {
                std::cerr << "Couldn't find transfer.info" << std::endl;
                exit(1);
            }
            std::getline(transfer, name);
            std::getline(transfer, name);
            transfer.close();

            // create rsaWrapper
            rsaWrap = new RSAPrivateWrapper();
        }
    }

    ~Client()
    {
        // Cleanup Winsock
        WSACleanup();
        delete rsaWrap;
    }

    int request(uint16_t req_code);

private:

    int register_req();
    int connect_req(int reconnect_flag);
    int send_req();
    int filename_payload_req(uint16_t req_code);
};