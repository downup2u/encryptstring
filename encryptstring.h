#ifndef _ENCRYPT_STRING_INCLUDE_H
#define _ENCRYPT_STRING_INCLUDE_H

#include <string>

bool encodeString(const std::string& source, std::string&sout);
bool decodeString(const std::string& source, std::string&sout);
bool encodeString_Hex(const std::string& source, std::string&sout);
bool decodeString_Hex(const std::string& source, std::string&sout);
std::string generateRandomSn();
#endif // _ESCAPE_STRING_INCLUDE_H
