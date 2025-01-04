#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <cctype>
#include <set>
#include <regex>

using namespace std;

// Frecuencias típicas de letras en inglés (aproximadas)
const string ENGLISH_LETTER_FREQUENCY = "etaoinshrdlcumwfgypbvkjxqz";

// Función para contar la frecuencia de letras en un texto
unordered_map<char, int> contarFrecuenciaLetras(const string& texto) {
    unordered_map<char, int> frecuencia;
    for (char c : texto) {
        if (isalpha(c)) {
            char lower = tolower(c);
            frecuencia[lower]++;
        }
    }
    return frecuencia;
}

// Función para ordenar las letras por frecuencia
vector<pair<char, int>> ordenarPorFrecuencia(const unordered_map<char, int>& frecuencia) {
    vector<pair<char, int>> frecuenciaVec(frecuencia.begin(), frecuencia.end());
    sort(frecuenciaVec.begin(), frecuenciaVec.end(), [](const pair<char, int>& a, const pair<char, int>& b) {
        return b.second > a.second; // Ordenar de mayor a menor frecuencia
    });
    return frecuenciaVec;
}

// Función para generar un mapa de sustitución basado en frecuencias
unordered_map<char, char> generarMapaSustitucion(const vector<pair<char, int>>& frecuenciaVec) {
    unordered_map<char, char> mapaSustitucion;
    for (size_t i = 0; i < frecuenciaVec.size() && i < ENGLISH_LETTER_FREQUENCY.size(); ++i) {
        mapaSustitucion[frecuenciaVec[i].first] = ENGLISH_LETTER_FREQUENCY[i];
    }
    return mapaSustitucion;
}

// Función para ajustar el mapa de sustitución utilizando la palabra pista
void ajustarMapaConPista(unordered_map<char, char>& mapaSustitucion, const string& textoCifrado, const string& palabraPista) {
    size_t pos = textoCifrado.find(palabraPista);
    if (pos != string::npos) {
        for (size_t i = 0; i < palabraPista.size(); ++i) {
            char cifrado = tolower(textoCifrado[pos + i]);
            char original = tolower(palabraPista[i]);
            mapaSustitucion[cifrado] = original;
        }
    }
}

// Función para descifrar el texto utilizando el mapa de sustitución
string descifrarConMapa(const unordered_map<char, char>& mapaSustitucion, const string& textoCifrado) {
    string textoDescifrado;
    for (char c : textoCifrado) {
        char lower = tolower(c);
        if (mapaSustitucion.find(lower) != mapaSustitucion.end()) {
            char descifrado = mapaSustitucion.at(lower);
            textoDescifrado += isupper(c) ? toupper(descifrado) : descifrado;
        } else {
            textoDescifrado += c;
        }
    }
    return textoDescifrado;
}

// Función principal para descifrar por criptoanálisis de frecuencia con una palabra pista
string frequencyAnalysisDecipherWithClue(const string& textoCifrado, const string& palabraPista) {
    // Contar la frecuencia de letras en el texto cifrado
    auto frecuencia = contarFrecuenciaLetras(textoCifrado);

    // Ordenar las letras por frecuencia
    auto frecuenciaVec = ordenarPorFrecuencia(frecuencia);

    // Generar el mapa de sustitución basado en frecuencias
    auto mapaSustitucion = generarMapaSustitucion(frecuenciaVec);

    // Ajustar el mapa de sustitución utilizando la palabra pista
    ajustarMapaConPista(mapaSustitucion, textoCifrado, palabraPista);

    // Descifrar el texto utilizando el mapa de sustitución ajustado
    return descifrarConMapa(mapaSustitucion, textoCifrado);
}

int main() {
    // Ejemplo de texto cifrado y palabra pista
    string textoCifrado = "Gsv jfrxp yildm ulc qfnkh levi gsv ozab wlt";
    string palabraPista = "example";

    // Descifrar el texto utilizando criptoanálisis de frecuencia con una palabra pista
    string textoDescifrado = frequencyAnalysisDecipherWithClue(textoCifrado, palabraPista);
    cout << "Texto descifrado: " << textoDescifrado << endl;

    return 0;
}