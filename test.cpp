#include <climits>
#include <cmath>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <random>
#include <string>
#include <vector>

#include "src/OAEP.h"
#include "src/RSA.h"

// test.cpp prototypes
int promptLoop();

// Quick string hash functions from the below SO link (only slightly modified). Used for (slightly slower) switch cases with strings because
// it's fun
uint32_t hash(const std::string& s) noexcept;
constexpr uint32_t hash(const char* s, size_t sz) noexcept {
    uint32_t hash = 5381;
    for (size_t i = 0; i < sz; i++) hash = ((hash << 5) + hash) + (unsigned char)s[i];
    return hash;
}

// Thank you "marco" and "Nick" on SO for this neat trick: https://stackoverflow.com/a/69720722/7359826
constexpr inline uint32_t operator"" _(char const* p, size_t s) { return hash(p, s); }

int main(int argc, char* argv[]) {

    if (argc > 1) {
        // TODO: Implement command line arguments
        std::cout << "Command line arguments not supported yet.\n"
                     "Running prompt loop as a fallback...\n";

        return promptLoop();
    } else {
        // If no args are provided, run interactive prompt loop
        return promptLoop();
    }
}

int promptLoop() {
    // Bind SIGINT handler
    signal(SIGINT, [](int sig) {
        std::cout << "\nCaught SIGINT. Exiting...\n";
        exit(0);
    });

    // Begin loop
    std::cout << "Enter a command (Type 'help' or just 'h' for a list of commands, use ctrl+C, ctrl+D, or type \"exit\" to exit):\n";
    std::unique_ptr<RSA> rsa = nullptr; // The "loaded" RSA key/keypair
    std::string line;

    for (std::cout << "Command> "; std::cin >> line && line != "exit" && line != "quit" && line != "q"; std::cout << "Command> ") {
        switch (hash(line)) {
        case "help"_:
        case "h"_:
            std::cout << "Commands:\n"
                      << std::setw(35) << std::left << "load|l <keyfile>" << std::right
                      << ": Load a key or keypair from a file. Will specify whether\n"
                      << std::setw(35) << std::left << "" << std::right
                      << "  the program was able to find a full keypair or just the public key.\n"
                      << std::setw(35) << std::left << "gen|g <keylength>" << std::right
                      << ": Generate a keypair with bit-length <keylength> and load it.\n"
                      << std::setw(35) << std::left << "encrypt|e" << std::right
                      << ": Encrypt a message with the loaded public key. Message should be entered on the\n"
                      << std::setw(35) << std::left << "" << std::right << "  following line and terminated with the line \"END MSG\"\n"
                      << std::setw(35) << std::left << "decrypt|d" << std::right
                      << ": Decrypt a ciphertext with the loaded private key. Ciphertext should be entered on\n"
                      << std::setw(35) << std::left << "" << std::right << "  a single line following the command.\n"
                      << std::setw(35) << std::left << "store|s <keyfile> PRIVATE? WEB?" << std::right
                      << ": Stores the currently loaded key to file <keyfile>. If \"PRIVATE\" is specified,\n"
                      << std::setw(35) << std::left << "" << std::right
                      << "  the full keypair with private key will be stored. If \"WEB\" is, then the key\n"
                      << std::setw(35) << std::left << "" << std::right << "  will be formatted for use with rsa.jacobcohen.dev only.\n"
                      << std::setw(35) << std::left << "clear|c" << std::right
                      << ": Clear the screen with ANSI codes (if your terminal supports that)\n"
                      << std::setw(35) << std::left << "fingerprint|f" << std::right
                      << ": Show the fingerprint of the currently loaded key.\n"
                      << std::setw(35) << std::left << "sign" << std::right
                      << ": Sign a message with the loaded private key. Message should be entered on the\n"
                      << std::setw(35) << std::left << "" << std::right << "  following line and terminated with the line \"END MSG\"\n"
                      << std::setw(35) << std::left << "verify|v" << std::right
                      << ": Verify a message's integrity against the loaded public key. Full signed message should\n"
                      << std::setw(35) << std::left << "" << std::right << "  be entered on the following line.\n"
                      << std::setw(35) << std::left << "help|h" << std::right << ": Display this message\n"
                      << std::setw(35) << std::left << "exit|quit|q" << std::right << ": Exit the program\n";
            break;
        case "load"_:
        case "l"_: {
            std::string keyfile;
            char c;
            for (size_t i = 0; (c = getc(stdin)) != ' ' && c != '\n'; i++) {
            }

            if (c == '\n') {
                std::cout << "Invalid keyfile. Type 'help' or just 'h' for a list of commands.\n";
                break;
            }

            std::getline(std::cin, keyfile);

            if (!keyfile.size()) {
                std::cout << "Invalid keyfile. Type 'help' or just 'h' for a list of commands.\n";
                break;
            }

            try {
                /* The monadic operations for std::optional are only available in the experimental C++23, so I will just use value_or() for
                 * now. */
                rsa = std::make_unique<RSA>(RSA::buildFromKeyFile(keyfile.c_str(), true).value_or(RSA::empty()));
            } catch (std::runtime_error& e) {
            }

            if (!*rsa) {
                try {
                    rsa = std::make_unique<RSA>(RSA::buildFromKeyFile(keyfile.c_str(), false).value_or(RSA::empty()));
                } catch (std::runtime_error& e) {
                }
            } else {
                std::cout << "Loaded keypair from file.\n";
                break;
            }

            if (!*rsa) {
                std::cout << "Failed to load keypair from file!\n";
                rsa = nullptr;
            } else {
                std::cout << "Loaded public key from file.\n";
            }
            break;
        }
        case "gen"_:
        case "g"_: {
            uint16_t keylength;
            std::string keylengthStr;

            char c;
            for (size_t i = 0; (c = getc(stdin)) != ' ' && c != '\n'; i++) {
            }

            if (c == '\n') {
                std::cout << "Invalid key length. Type 'help' or just 'h' for a list of commands.\n";
                break;
            }

            std::getline(std::cin, keylengthStr);

            // Do an atoi() on the keylength string
            try {
                keylength = std::stoi(keylengthStr);
            } catch (std::invalid_argument& e) {
                std::cout << "Invalid key length. Type 'help' or just 'h' for a list of commands.\n";
                break;
            }

            std::cout << "Attempting " << keylength << "-bit RSA keypair generation...\n";
            try {
                rsa = std::make_unique<RSA>(RSA(keylength));
            } catch (std::runtime_error& e) {
                std::cout << "Failed to generate keypair. Reason:\t" << e.what() << "\n";
                break;
            }

            std::cout << "Generated keypair.\n";

            break;
        }
        case "encrypt"_:
        case "e"_: {
            while (getc(stdin) != '\n') {
            }
            if (!rsa) {
                std::cout << "No key loaded. Use 'load' or 'gen' to load or generate a key.\n";
                break;
            }
            std::cout << "Enter message to encrypt (remember to terminate with \"END MSG\" on its own line):\n";
            std::string toEncrypt;
            while (std::getline(std::cin, line) && line != "END MSG") {
                toEncrypt += line + "\n";
            }

            std::cout << "Encrypted message:\n" << rsa->encrypt(toEncrypt, true) << "\n";
            break;
        }
        case "decrypt"_:
        case "d"_: {
            if (!rsa) {
                std::cout << "No key loaded. Use 'load' or 'gen' to load or generate a key.\n";
                break;
            }

            if (!rsa->getPrivateKey()) {
                std::cout << "No private key loaded. Use 'load' to load a keypair.\n";
                break;
            }

            std::cout << "Enter message to decrypt:\n";
            std::string toDecrypt;
            std::cin >> toDecrypt; // There can be no spaces or new line characters in encrypted messages with my RSA, so this is fine.

            std::string decrypted = "";
            try {
                decrypted = rsa->decrypt(toDecrypt, true);
            } catch (std::runtime_error& e) {
            }

            if (!decrypted.size()) {
                try {
                    decrypted = rsa->decrypt(toDecrypt, false);
                } catch (std::runtime_error& e) {
                    std::cout << "Failed to decrypt message. Reason:\t" << e.what() << "\n";
                    break;
                }
            }

            std::cout << "Decrypted message:\n" << decrypted << "\n";

            break;
        }
        case "clear"_:
        case "c"_:
            std::cout << "\e[2J\e[1;1H";
            break;
        case "store"_:
        case "s"_: {
            if (!rsa) {
                std::cout << "No key loaded. Use 'load' or 'gen' to load or generate a key.\n";
                break;
            }

            std::string keyfile;

            char c;
            for (size_t i = 0; (c = getc(stdin)) != ' ' && c != '\n'; i++) {
            }

            if (c == '\n') {
                std::cout << "Invalid keyfile. Type 'help' or just 'h' for a list of commands.\n";
                break;
            }

            std::getline(std::cin, keyfile);

            size_t minCutoff = SIZE_MAX;

            bool includePrivate = false;
            if (keyfile.find("PRIVATE") != std::string::npos) {
                includePrivate = true;
                size_t pos = keyfile.find("PRIVATE");
                if (pos < minCutoff) {
                    minCutoff = pos;
                }
            }

            bool webFormat = false;
            if (keyfile.find("WEB") != std::string::npos) {
                webFormat = true;
                size_t pos = keyfile.find("WEB");
                if (pos < minCutoff) {
                    minCutoff = pos;
                }
            }

            if (minCutoff != SIZE_MAX) {
                keyfile = keyfile.substr(0, minCutoff - 1);
            }

            if (!keyfile.size() || std::all_of(keyfile.begin(), keyfile.end(), [](char c) { return std::isspace(c); })) {
                std::cout << "Invalid keyfile. Type 'help' or just 'h' for a list of commands.\n";
                break;
            }

            try {
                if (!rsa->exportToFile(keyfile.c_str(), includePrivate, webFormat)) {
                    std::cout << "Exported " << (includePrivate ? "keypair" : "public key") << " to file.\n";
                }
            } catch (std::runtime_error& e) {
                std::cout << "Failed to export keypair to file! Reason:\t" << e.what() << "\n";
            }

            break;
        }
        case "f"_:
        case "fingerprint"_: {
            if (!rsa) {
                std::cout << "No key loaded. Use 'load' or 'gen' to load or generate a key.\n";
                break;
            }

            std::cout << "Fingerprint:\t" << rsa->getFingerprint() << "\n";
            break;
        }
        case "sign"_: {
            if (!rsa) {
                std::cout << "No key loaded. Use 'load' or 'gen' to load or generate a key.\n";
                break;
            }

            if (!rsa->getPrivateKey()) {
                std::cout << "No private key loaded. Use 'load' to load a keypair.\n";
                break;
            }

            std::cout << "Enter message to sign (remember to terminate with \"END MSG\" on its own line):\n";
            std::string toSign;
            while (std::getline(std::cin, line) && line != "END MSG") {
                toSign += line + "\n";
            }

            std::cout << "\n\nSigned message below:\n\n" << rsa->sign(toSign) << "\n";
            break;
        }
        case "verify"_:
        case "v"_: {
            if (!rsa) {
                std::cout << "No key loaded. Use 'load' or 'gen' to load or generate a key.\n";
                break;
            }

            std::cout << "Enter signed message to verify:\n";
            std::string signedMessage;
            while (std::getline(std::cin, line) && line != "----- END RSA SIGNED MESSAGE -----") {
                signedMessage += line + "\n";
            }
            signedMessage += line;

            std::cout << "\n\n"
                      << (rsa->verify(signedMessage) ? "\e[1;32mMessage verified successfully!\e[0m\n"
                                                     : "\e[1;31mMessage verification failed!\e[0m\n");
            break;
        }
        default:
            std::cout << "Command not recognized. Type 'help' or just 'h' for a list of commands.\n";
            break;
        }
    }

    std::cout << "\nExiting...\n";
    return 0;
}

uint32_t hash(const std::string& s) noexcept {
    uint32_t hash = 5381;
    for (const auto& c : s) hash = ((hash << 5) + hash) + (unsigned char)c;
    return hash;
}