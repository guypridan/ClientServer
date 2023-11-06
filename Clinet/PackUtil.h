#pragma once
#include <fstream>
#pragma once
#include <filesystem>
#include <iostream>
#include <string>
#include <cstdint>

#include "AESWrapper.h"
#include "RSAWrapper.h"
#include "Base64Wrapper.h"

#define MSG_SIZE 1024
#define CID_SIZE 16
#define REGISTER 1025

void pack_header(char* buffer, char* ClientID, uint8_t cli_version, uint16_t reqCode, uint32_t payloadSize);
void clean_buffer(char* buffer);
uint16_t unpack_code(char* code);
void unpack_bytes(char* dest, char* src, unsigned int len);
uint32_t get_payload_size(char* buffer);
std::string get_file_path();
std::string encrypt_file(std::string s_path, std::string aes_key);