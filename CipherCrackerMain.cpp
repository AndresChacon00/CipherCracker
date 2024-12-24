#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <vector>
#include <algorithm>
#include <mutex>
#include <thread>
#include <future>
#include <unordered_set>

#define ALPHABET_SIZE 26
#define LETTER_TO_INT(c) (int)(c - 'a')
#define INT_TO_LETTER(i) (char)(i + 'a')

using namespace std;

const string BASE_ALPHABET = "abcdefghijklmnopqrstuvwxyz";

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
 * Muestra la clave de descifrado en pantalla
 * @param keyMap La clave de cifrado a mostrar
 */
void printKeyMap(vector<char> &keyMap)
{
    for (int i = 0; i < keyMap.size(); i++)
    {
        cout << INT_TO_LETTER(i) << ":" << keyMap[i] << "; ";
    }
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

/**
 * Decifra un texto utilizando fuerza bruta, requiere una palabra pista
 * @param cipheredText Texto a descifrar
 * @param clueWord Palabra pista incluida en el texto
 */
string bruteForceDecipherWithClue(const string &cipheredText, const string &clueWord)
{
    // Convert to lowercase
    string lowerCipheredText = cipheredText;
    string lowerClueWord = clueWord;
    transform(lowerCipheredText.begin(), lowerCipheredText.end(), lowerCipheredText.begin(), ::tolower);
    transform(lowerClueWord.begin(), lowerClueWord.end(), lowerClueWord.begin(), ::tolower);

    // Find all unique ciphered words of the same length as clueWord
    unordered_set<string> uniqueWords;
    regex wordRegex("\\b\\w{" + to_string(clueWord.size()) + "}\\b");
    auto wordsBegin = sregex_iterator(lowerCipheredText.begin(), lowerCipheredText.end(), wordRegex);
    auto wordsEnd = sregex_iterator();

    for (sregex_iterator i = wordsBegin; i != wordsEnd; ++i)
    {
        // Check that the word is not in uniqueWords
        string cipheredWord = (*i).str();
        if (uniqueWords.find(cipheredWord) == uniqueWords.end())
        {
            uniqueWords.insert((*i).str());

            // Create copy of base alphabet but remove all letters from cipheredWord
            string alphabetCopy = BASE_ALPHABET;
            for (char c : cipheredWord)
            {
                alphabetCopy.erase(remove(alphabetCopy.begin(), alphabetCopy.end(), c), alphabetCopy.end());
            }
            cout << "Alphabet: " << alphabetCopy << "; cipheredWord: " << cipheredWord << '\n';

            // Generate all permutations of alphabet
            vector<char> keyMap(ALPHABET_SIZE, 0);
            for (int i = 0; i < clueWord.size(); i++)
            {
                keyMap[LETTER_TO_INT(lowerClueWord[i])] = cipheredWord[i];
            }

            do
            {
                // Generate keyMap with clueWord constraint
                int alphabetPos = 0;
                for (int i = 0; i < ALPHABET_SIZE; i++)
                {
                    bool shouldAdd = true;
                    for (char c : lowerClueWord)
                    {
                        if (LETTER_TO_INT(c) == i)
                        {
                            shouldAdd = false;
                            break;
                        }
                    }
                    if (shouldAdd)
                    {
                        keyMap[i] = alphabetCopy[alphabetPos++];
                    }
                }

                // Test decipher
                cout << monoalphabeticDecipher(keyMap, cipheredText) << " // ";
                printKeyMap(keyMap);
                cout << '\n';
            } while (next_permutation(alphabetCopy.begin(), alphabetCopy.end()));
        }
    }

    return "";
}

int main()
{
    // auto keyMap = readKeyFromJSON("key.json");
    // for (int i = 0; i < keyMap.size(); i++)
    // {
    //     cout << INT_TO_LETTER(i) << " -> " << keyMap[i] << '\n';
    // }

    // Ejemplo de cifrado
    // string texto = "Hola mundo";
    // string textoCifrado = monoalphabeticCipher(keyMap, texto);
    // string textoDescifrado = monoalphabeticDecipher(keyMap, textoCifrado);
    // cout << "Texto cifrado: " << textoCifrado << '\n';
    // cout << "Texto descifrado: " << textoDescifrado << '\n';

    string input = "VIRFW EIXYW VD UUAVW JWVDU QJAMUSW";
    string clueWord = "BRAWLIO";
    bruteForceDecipherWithClue(input, clueWord);
    // cout << "Salida: " << bruteForceDecipherWithClue(input, clueWord) << '\n';
    return 0;
}
