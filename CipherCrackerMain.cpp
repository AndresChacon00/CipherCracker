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
#define LETTER_TO_INT(c) c - 'a'
#define INT_TO_LETTER(i) i + 'a'

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
        uniqueWords.insert((*i).str());
    }

    mutex mtx;
    string result = "";
    const size_t numThreads = thread::hardware_concurrency();
    vector<future<void>> futures;

    auto worker = [&](const string &word)
    {
        string alphabet = BASE_ALPHABET;
        do
        {
            vector<char> keyMap(ALPHABET_SIZE, 0);
            bool valid = true;
            for (size_t i = 0; i < word.size(); ++i)
            {
                char c = word[i];
                char clue = lowerClueWord[i];
                if (keyMap[LETTER_TO_INT(clue)] == 0)
                {
                    keyMap[LETTER_TO_INT(clue)] = c;
                }
                else if (keyMap[LETTER_TO_INT(clue)] != c)
                {
                    valid = false;
                    break;
                }
            }
            if (valid)
            {
                string decipheredText = monoalphabeticDecipher(keyMap, lowerCipheredText);
                if (decipheredText.find(lowerClueWord) != string::npos)
                {
                    lock_guard<mutex> lock(mtx);
                    if (result.empty())
                    {
                        result = decipheredText;
                        cout << "Deciphered Text: " << result << endl;
                    }
                }
            }
        } while (next_permutation(alphabet.begin(), alphabet.end()));
    };

    for (const auto &word : uniqueWords)
    {
        if (futures.size() >= numThreads)
        {
            for (auto &fut : futures)
            {
                fut.get();
            }
            futures.clear();
        }
        futures.push_back(async(launch::async, worker, word));
    }

    for (auto &fut : futures)
    {
        fut.get();
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

    string input = "DXCY WQ CCYWX HXWQC IGCLY O WQ UJIKY SJUYH ZHYNC IKYHI";
    string clueWord = "BRAWL";
    bruteForceDecipherWithClue(input, clueWord);
    // cout << "Salida: " << bruteForceDecipherWithClue(input, clueWord) << '\n';
    return 0;
}
