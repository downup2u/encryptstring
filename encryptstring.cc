#include "encryptstring.h"
#include "md5.h"
#include "aes.h"
#include <boost/algorithm/hex.hpp>
#include <boost/random.hpp>
#include <boost/uuid/uuid.hpp>   
#include <boost/uuid/uuid_generators.hpp>   
#include <boost/uuid/uuid_io.hpp> 
#include <iostream>

const std::string password = "iteasysofttask";

std::string generateRandomSn()
{
	boost::uuids::random_generator rgen;
	boost::uuids::uuid ranUUID = rgen();
	std::stringstream ss;
	ss << ranUUID;
	return ss.str();
}

bool encodeString(const std::string& source,std::string&sout){

	//MD5 md5(password.data(), password.size());
	//std::string key = md5.toString();
	std::string key = "41E06604D64E83607AB63C199DF269A1";

	sout.clear();
	std::string sRawData = source;
	std::string sRawKey = boost::algorithm::unhex(key);
	int sizeRawData = sRawData.size();
	sRawData.resize(sizeRawData + (16 - sizeRawData % 16));
	for (int n = 0; n < (16 - sizeRawData % 16); n++)
	{
		sRawData[sizeRawData + n] = (16 - sizeRawData % 16);
	}
	uint8_t cSrc[16] = { 0 };
	uint8_t cDst[16] = { 0 };
	int nEncryptedLen = 16;
	for (int i = 0; i < sizeRawData; i += 16)
	{
		nEncryptedLen = 16;
		memset(cSrc, 0, sizeof(cSrc));
		memcpy(cSrc, sRawData.data() + i, nEncryptedLen);
		ecb_aes_encrypt(cSrc, 16, cDst, (const uint8_t*)sRawKey.data());
		std::string sHexData = boost::algorithm::hex(std::string((char*)cDst, 16));
		sout += sHexData;
	}
	return true;
}


bool decodeString(const std::string& source,std::string&sout)
{
	//MD5 md5(password.c_str(), password.size());
	//std::string key = md5.toString();
	std::string key = "41E06604D64E83607AB63C199DF269A1";

	sout.clear();
	sout = source;
	if (source.size() % 16 != 0 || source.empty()){
		return false;
	}
	for (int i = 0; i < source.size(); i++){
		if (source[i] >= '0' && source[i] <= '9')
			continue;
		if (source[i] >= 'a' && source[i] <= 'f')
			continue;
		if (source[i] >= 'A' && source[i] <= 'F')
			continue;
		return false;
	}

	sout.clear();
	std::string sRawData = boost::algorithm::unhex(source);
	std::string sRawKey = boost::algorithm::unhex(key);
	std::string sRawRetData;
	uint8_t cSrc[16] = { 0 };
	uint8_t cDst[16] = { 0 };
	int nEncryptedLen = 16;
	int nRawDataSize = sRawData.size();
	for (int i = 0; i < nRawDataSize; i += 16)
	{
		nEncryptedLen = (i + 16) < nRawDataSize ? 16 : nRawDataSize - i;
		memset(cSrc, 0, sizeof(cSrc));
		memcpy(cSrc, sRawData.data() + i, nEncryptedLen);
		ecb_aes_decrypt(cSrc, 16, cDst, (const uint8_t*)sRawKey.data());
		sRawRetData += std::string((char*)cDst, 16);
	}
	int nRawRetDataSize = sRawRetData.size();//no size_t,for n > always return true
	int n = nRawRetDataSize - 1;
	for (; n >= nRawRetDataSize - 16 && n > 0; n--)
	{
		if (1 <= sRawRetData[n] && 16 >= sRawRetData[n])
		{
			sRawRetData[n] = 0;
		}
		else
		{
			break;
		}
	}
	sRawRetData.resize(n + 1);
	sout = sRawRetData;
	return true;
}


bool encodeString_Hex(const std::string& source, std::string&sout){

	sout = boost::algorithm::hex(source);
	return true;
}


bool decodeString_Hex(const std::string& source, std::string&sout)
{
	sout = boost::algorithm::unhex(source);
	return true;
}


