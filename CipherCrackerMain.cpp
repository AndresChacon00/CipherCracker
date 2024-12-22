#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <vector>

#define ALPHABET_SIZE 26
#define LETTER_TO_INT(c) c - 'a'
#define INT_TO_LETTER(i) i + 'a'

using namespace std;

char BASE_ALPHABET[] = {
    'a',
    'b',
    'c',
    'd',
    'e',
    'f',
    'g',
    'h',
    'i',
    'j',
    'k',
    'l',
    'm',
    'n',
    'o',
    'p',
    'q',
    'r',
    's',
    't',
    'u',
    'v',
    'w',
    'x',
    'y',
    'z'};

/**
 * Lee la clave de encriptación a partir de un archivo JSON
 * @param f Ruta del archivo
 */
vector<char> readKeyFromJSON(const string &f)
{
    ifstream file(f);
    vector<char> keyMap(ALPHABET_SIZE);

    if (!file.is_open())
    {
        cerr << "No se pudo abrir el archivo: " << f << endl;
        return keyMap;
    }

    string line;

    regex kv_regex(R"("\s*([a-zA-Z])\s*"\s*:\s*"\s*([a-zA-Z])\s*"\s*,?)");
    smatch match;

    while (getline(file, line))
    {
        if (regex_search(line, match, kv_regex))
        {
            if (match.size() == 3)
            {
                // Read mapping
                char key = match[1].str()[0];
                char value = match[2].str()[0];
                key = tolower(key);

                // Add to key map
                int pos = LETTER_TO_INT(key);
                keyMap[pos] = tolower(value);
            }
        }
    }

    file.close();
    return keyMap;
}

/**
 * Cifra un texto utilizando un cifrado monoalfabético
 * @param keyMap Clave de cifrado
 * @param originalText Texto a cifrar
 */
string monoalphabeticCipher(vector<char> &keyMap, const string &originalText)
{
    string cipherText = "";
    for (char c : originalText)
    {
        char lower = tolower(c);
        int pos = LETTER_TO_INT(lower);
        if (keyMap.size() > pos)
        {
            char cipher = keyMap.at(pos);
            cipherText += isupper(c) ? toupper(cipher) : cipher;
        }
        else
        {
            cipherText += c;
        }
    }
    return cipherText;
}

/**
 * Descifra un texto utilizando un cifrado monoalfabético
 * @param keyMap Clave de cifrado
 * @param cipheredText Texto a descifrar
 */
string monoalphabeticDecipher(vector<char> &keyMap, const string &cipheredText)
{
    // Create an inverse map of the key
    vector<char> inverseKeyMap(keyMap.size());
    for (int i = 0; i < keyMap.size(); i++)
    {
        // Example: keyMap[3] = 'a' means inverseKeyMap[0] = 'd'
        char c = keyMap[i];
        char letterInInverse = INT_TO_LETTER(i);
        int posInInverse = LETTER_TO_INT(c);
        inverseKeyMap[posInInverse] = letterInInverse;
    }

    // Decipher with inverseKeyMap
    string originalText = "";
    for (char c : cipheredText)
    {
        char lower = tolower(c);
        int pos = LETTER_TO_INT(lower);
        if (inverseKeyMap.size() > pos)
        {
            char cipher = inverseKeyMap.at(pos);
            originalText += isupper(c) ? toupper(cipher) : cipher;
        }
        else
        {
            originalText += c;
        }
    }
    return originalText;
}

int main()
{
    auto keyMap = readKeyFromJSON("key.json");
    for (int i = 0; i < keyMap.size(); i++)
    {
        cout << INT_TO_LETTER(i) << " -> " << keyMap[i] << '\n';
    }

    // Ejemplo de cifrado
    string texto = "Hola mundo";
    string textoCifrado = monoalphabeticCipher(keyMap, texto);
    string textoDescifrado = monoalphabeticDecipher(keyMap, textoCifrado);
    cout << "Texto cifrado: " << textoCifrado << '\n';
    cout << "Texto descifrado: " << textoDescifrado << '\n';
}
