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
#include <set>

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
 * Carga un diccionario (lista) de palabras en inglés
 * @param dictionaryPath Ruta del archivo del diccionario
 */
set<string> loadDictionary(const string &dictionaryPath)
{
    set<string> dictionary;
    ifstream file(dictionaryPath);
    if (file.is_open())
    {
        string word;
        while (getline(file, word))
        {
            dictionary.insert(word);
        }
        file.close();
    }
    else
    {
        cerr << "Error opening dictionary file: " << dictionaryPath << endl;
    }
    return dictionary;
}

/**
 * Verifica que todas las palabras de `text` estén en `dictionary`
 * @param text Texto a validar
 * @param dictionary Diccionario cargado en memoria
 */
bool checkAllWordsInDictionary(const string &text, const set<string> &dictionary)
{
    regex wordRegex("\\b\\w+\\b"); // Matches one or more word characters
    auto wordsBegin = sregex_iterator(text.begin(), text.end(), wordRegex);
    auto wordsEnd = sregex_iterator();

    for (sregex_iterator i = wordsBegin; i != wordsEnd; ++i)
    {
        string word = (*i).str();
        transform(word.begin(), word.end(), word.begin(), ::tolower);
        if (dictionary.find(word) == dictionary.end())
        {
            return false; // Word not found in dictionary
        }
    }
    return true; // All words found
}

/**
 * Compara los patrones de caracteres entre dos palabras, es decir, si es posible cifrar una para obtener la otra
 * @param word1 First word
 * @param word2 Second word
 */
bool matchWordsPattern(const string &word1, const string &word2)
{
    if (word1.size() != word2.size())
    {
        return false;
    }

    unordered_map<char, char> map1, map2;
    for (size_t i = 0; i < word1.size(); ++i)
    {
        char c1 = word1[i];
        char c2 = word2[i];

        if (map1.find(c1) == map1.end())
        {
            map1[c1] = c2;
        }
        if (map2.find(c2) == map2.end())
        {
            map2[c2] = c1;
        }

        if (map1[c1] != c2 || map2[c2] != c1)
        {
            return false;
        }
    }

    return true;
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
    // Load dictionary
    set<string> dictionary = loadDictionary("english.txt");
    if (dictionary.empty())
    {
        return ""; // Return empty string if dictionary loading failed
    }

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
        // Check that word has correct pattern
        string cipheredWord = (*i).str();
        if (!matchWordsPattern(lowerClueWord, cipheredWord))
        {
            continue;
        }

        // Check that the word is not in uniqueWords
        if (uniqueWords.find(cipheredWord) == uniqueWords.end())
        {
            uniqueWords.insert((*i).str());

            // Create copy of base alphabet but remove all letters from cipheredWord
            string alphabetCopy = BASE_ALPHABET;
            for (char c : cipheredWord)
            {
                alphabetCopy.erase(remove(alphabetCopy.begin(), alphabetCopy.end(), c), alphabetCopy.end());
            }

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
                string decipheredText = monoalphabeticDecipher(keyMap, cipheredText);
                if (checkAllWordsInDictionary(decipheredText, dictionary))
                {
                    cout << "Texto descifrado: " << decipheredText << '\n';
                    printKeyMap(keyMap);
                    return decipheredText;
                }
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

    string input = "I LIKE PLAXING BRAWL STARS EVERX DAX";
    string clueWord = "PLAYING";
    bruteForceDecipherWithClue(input, clueWord);
    // cout << "Salida: " << bruteForceDecipherWithClue(input, clueWord) << '\n';
    return 0;
}
