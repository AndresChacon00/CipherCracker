#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <regex>

using namespace std;

unordered_map<char, char> readKeyFromJSON(const string& f) {
    ifstream file(f);
    unordered_map<char, char> keyMap;

    if (!file.is_open()) {
        cerr << "No se pudo abrir el archivo: " << f << endl;
        return keyMap;
    }
    
    string line;

    regex kv_regex(R"("\s*([a-zA-Z])\s*"\s*:\s*"\s*([a-zA-Z])\s*"\s*,?)");
    smatch match;

    while (getline(file, line)) {
        if (regex_search(line, match, kv_regex)) {
            if (match.size() == 3) {
                char key = match[1].str()[0];
                char value = match[2].str()[0];
                keyMap[key] = value;
            }
        }
    }

    file.close();
    return keyMap;
}

string monoalphabeticCipher(unordered_map<char, char> keyMap ,string originalText) {
    string cipherText ="";
    for (char c : originalText) {
        char lower = tolower(c);
        if (keyMap.find(lower) != keyMap.end()) {
            char cipher = keyMap.at(lower);
            cipherText += isupper(c) ? toupper(cipher) : cipher;
        } else {
            cipherText += c;
        }
    }
    return cipherText;
}

string monoalphabeticDecipher(unordered_map<char, char> keyMap, string cipheredText) {
    // Create an inverse map of the key
    unordered_map<char, char> inverseKeyMap;
    for (const auto& pair: keyMap ) {
        inverseKeyMap[pair.second] = pair.first;
    }

    // Descipher with inverseKeyMap
    string originalText = "";
    for(char c : cipheredText) {
        char lower = tolower(c);
        if (inverseKeyMap.find(lower) != inverseKeyMap.end()) {
            char cipher = inverseKeyMap.at(lower);
            originalText += isupper(c) ? toupper(cipher) : cipher;
        } else {
            originalText += c;
        }
    }
    return originalText;
}

int main() {

    auto keyMap = readKeyFromJSON("key.json");
    for (const auto& pair : keyMap) {
        cout << pair.first << " -> "<< pair.second << endl;
    }

    // Ejemplo de cifrado
    string texto = "Hola mundo";
    string textoCifrado = monoalphabeticCipher(keyMap, texto);
    string textoDescifrado = monoalphabeticDecipher(keyMap, textoCifrado);
    cout << "Texto cifrado: " << textoCifrado <<endl;
    cout << "Texto descifrado: " << textoDescifrado <<endl;

}