#include <pybind11/pybind11.h>
#include "micro-ecc/uECC.h"


// Convertion d'1 char en bina
unsigned char hexchr2bin(const char hex)
{
	unsigned char result;

	if (hex >= '0' && hex <= '9') {
		result = hex - '0';
	} else if (hex >= 'A' && hex <= 'F') {
		result = hex - 'A' + 10;
	} else if (hex >= 'a' && hex <= 'f') {
		result = hex - 'a' + 10;
	} else {
		return 0;
	}
	return result;
}


// Convertion String en binary
void hexStringToBin(unsigned char *out,const char * hexPrivate) {
    for (int i=0; i<32; i++){
	out[i] = hexchr2bin(hexPrivate[2*i])<<4 | hexchr2bin(hexPrivate[2*i+1]);
    }
}

//Convertion bin en String 
char *binToHexString(char *out,const unsigned char *bin, size_t len)
{
    size_t  i;

    if (bin == NULL || len == 0)
	return NULL;

    for (i=0; i<len; i++) {
	out[i*2]   = "0123456789abcdef"[bin[i] >> 4];
	out[i*2+1] = "0123456789abcdef"[bin[i] & 0x0F];
    }
    out[len*2] = '\0';

    return out;
}








class Cle
{
	
    private:
        std::string Private_Key;
        std::string Public_Key;
	
    public:
         Cle() {}
        ~Cle() {}

        void initialize(std::string &Number) { 
		const struct uECC_Curve_t *curve = uECC_secp256k1(); // creer ECC type secp256k1 : elliptic curve used by Bitcoin
		uint8_t Cle_Prive_Binaire[32]; // initialiser array with 32 bits to save binary private key after converting frrom sstring
		hexStringToBin(Cle_Prive_Binaire,Number.c_str()); // convertion string entry private key to binary
		const int Private_Key_Size = uECC_curve_private_key_size(curve); // get Private key size
		const int Public_Key_Size=uECC_curve_public_key_size(curve); // get Public Key size
		uint8_t *Public_Key_Var = new uint8_t[Public_Key_Size]; // Creer new array ac public key size to save public key after cumputing
		uECC_compute_public_key(Cle_Prive_Binaire,Public_Key_Var,curve); // convertion private key to public key
		char Cle_Public_Hexa[128];// initialiser array with 128 bits to save hexadecimal publuc key after converting frrom unsign int 
		binToHexString(Cle_Public_Hexa,Public_Key_Var,64); // convertion unsign int public key to hexadecimal 
		Private_Key= Number; // Private Key is the entry value, with string type
		Public_Key=std::string(Cle_Public_Hexa,128); // Convertion Public key to string type
		}
		
        const std::string &getPrivateKey() const { 
		return Private_Key; }
	const std::string &getPublicKey() const { 
		return Public_Key; }

};

        
 namespace py = pybind11;
 
 PYBIND11_MODULE(composant_cle,Key) {
   py::class_<Cle>(Key, "Cle",py::dynamic_attr())
      	.def(py::init<>())
	.def("initialize", &Cle::initialize) 
        .def("getPrivateKey", &Cle::getPrivateKey)
        .def("getPublicKey", &Cle::getPublicKey);
 }
     
