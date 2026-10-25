CIPHER HUB — Complete Frontend (JavaScript Engine)

FILES
- index.html: page structure
- style.css: responsive dark cybersecurity design
- app.js: working SUPER, YAM and DANY encrypt/decrypt logic

HOW TO RUN
1. Extract the ZIP.
2. Open index.html in a modern browser (Chrome, Edge, Firefox).
3. Choose SUPER, YAM or DANY.
4. Encrypt: type plaintext, provide required key(s), click Encrypt message.
5. Decrypt: paste the HEX output, use the SAME mode and key(s), click Decrypt message.
6. Use Copy result to copy the result.

IMPORTANT COMPATIBILITY NOTES
- This JavaScript version mirrors the supplied C++ byte operations and uses UTF-8 bytes for both message and keys.
- Encryption output is uppercase HEX, matching the C++ toHex() function.
- DANY uses fixed K = [68, 65, 78, 89].
- For decrypt, the input must be HEX. If decrypted bytes are not valid UTF-8, the page displays recovered bytes as HEX.
- This version is fully browser-side; it does not need Node.js or a C++ compiler.

SECURITY WARNING
SUPER, YAM and DANY are custom educational algorithms and are not considered secure cryptographic algorithms. Do not use them to protect real passwords, personal data, or sensitive messages.
