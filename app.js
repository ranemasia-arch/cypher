'use strict';

// CIPHER HUB JavaScript engine.
// The operations below mirror the supplied C++ logic using UTF-8 bytes.
// These are custom educational ciphers, not secure modern cryptography.

const $ = (id) => document.getElementById(id);
const modeButtons = [...document.querySelectorAll('.mode-card')];
const encryptBtn = $('encryptBtn');
const decryptBtn = $('decryptBtn');
const key1Wrap = $('key1Wrap');
const key2Wrap = $('key2Wrap');
const fixedKeyNote = $('fixedKeyNote');
const key1 = $('key1');
const key2 = $('key2');
const inputText = $('inputText');
const inputLabel = $('inputLabel');
const inputFormat = $('inputFormat');
const charCount = $('charCount');
const runLabel = $('runLabel');
const runIcon = $('runIcon');
const notice = $('notice');
const outputBox = $('outputBox');
const outputType = $('outputType');
const outputCount = $('outputCount');
const copyBtn = $('copyBtn');

let selectedMode = 'super';
let operation = 'encrypt';
let lastOutput = '';

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

function setNotice(message, type = '') {
  notice.textContent = message;
  notice.className = `notice ${type}`.trim();
}
function toHex(bytes) {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('').toUpperCase();
}
function fromHex(hex) {
  const clean = hex.replace(/\s+/g, '');
  if (clean.length % 2 !== 0) throw new Error('Hex input must contain an even number of hexadecimal characters.');
  if (!/^[0-9a-fA-F]*$/.test(clean)) throw new Error('Invalid Hex input. Use only characters 0–9 and A–F.');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) bytes[i / 2] = parseInt(clean.slice(i, i + 2), 16);
  return bytes;
}
function keyBytes(key) { return encoder.encode(key); }

// C++ SUPER: (byte + keyByte + index) & 0xFF
function superEnc(input, key) {
  const k = keyBytes(key);
  if (!k.length) throw new Error('SUPER requires a non-empty key.');
  return Uint8Array.from(input, (b, i) => (b + k[i % k.length] + i) & 0xFF);
}
function superDec(input, key) {
  const k = keyBytes(key);
  if (!k.length) throw new Error('SUPER requires a non-empty key.');
  return Uint8Array.from(input, (b, i) => (b - k[i % k.length] - i + 512) & 0xFF);
}

// C++ YAM: chained previous ciphertext byte; prev starts at zero.
function yamEnc(input, keyA, keyB) {
  const a = keyBytes(keyA), b = keyBytes(keyB);
  if (!a.length || !b.length) throw new Error('YAM requires both non-empty keys.');
  const out = new Uint8Array(input.length);
  let prev = 0;
  for (let i = 0; i < input.length; i++) {
    const e = (input[i] + a[i % a.length] + b[i % b.length] + prev + i) & 0xFF;
    out[i] = e;
    prev = e;
  }
  return out;
}
function yamDec(input, keyA, keyB) {
  const a = keyBytes(keyA), b = keyBytes(keyB);
  if (!a.length || !b.length) throw new Error('YAM requires both non-empty keys.');
  const out = new Uint8Array(input.length);
  let prev = 0;
  for (let i = 0; i < input.length; i++) {
    const d = (input[i] - a[i % a.length] - b[i % b.length] - prev - i + 1024) & 0xFF;
    out[i] = d;
    prev = input[i];
  }
  return out;
}

// C++ DANY: fixed K = {68,65,78,89}; no user key.
const DANY_K = [68, 65, 78, 89];
function danyEnc(input) {
  const out = new Uint8Array(input.length);
  let prev = DANY_K[0];
  for (let i = 0; i < input.length; i++) {
    const shift = (DANY_K[i % 4] + prev + i) & 0xFF;
    const e = (input[i] + shift) & 0xFF;
    out[i] = e;
    prev = e;
  }
  return out;
}
function danyDec(input) {
  const out = new Uint8Array(input.length);
  let prev = DANY_K[0];
  for (let i = 0; i < input.length; i++) {
    const shift = (DANY_K[i % 4] + prev + i) & 0xFF;
    const d = (input[i] - shift + 256) & 0xFF;
    out[i] = d;
    prev = input[i];
  }
  return out;
}

function encryptBytes(input) {
  if (selectedMode === 'super') return superEnc(input, key1.value);
  if (selectedMode === 'yam') return yamEnc(input, key1.value, key2.value);
  return danyEnc(input);
}
function decryptBytes(input) {
  if (selectedMode === 'super') return superDec(input, key1.value);
  if (selectedMode === 'yam') return yamDec(input, key1.value, key2.value);
  return danyDec(input);
}
function refreshMode() {
  modeButtons.forEach(button => button.classList.toggle('active', button.dataset.mode === selectedMode));
  key1Wrap.classList.toggle('hidden', selectedMode === 'dany');
  key2Wrap.classList.toggle('hidden', selectedMode !== 'yam');
  fixedKeyNote.classList.toggle('hidden', selectedMode !== 'dany');
  $('keyFields').classList.toggle('hidden', selectedMode === 'dany');
}
function refreshOperation() {
  encryptBtn.classList.toggle('active', operation === 'encrypt');
  decryptBtn.classList.toggle('active', operation === 'decrypt');
  runLabel.textContent = operation === 'encrypt' ? 'Encrypt message' : 'Decrypt message';
  runIcon.textContent = operation === 'encrypt' ? '↗' : '↙';
  inputLabel.textContent = operation === 'encrypt' ? 'INPUT TEXT' : 'INPUT HEX CIPHERTEXT';
  inputText.placeholder = operation === 'encrypt' ? 'Type or paste your message here...' : 'Paste the hexadecimal ciphertext here...';
  inputFormat.textContent = operation === 'encrypt' ? 'PLAIN TEXT → HEX' : 'HEX CIPHERTEXT → TEXT';
}
function renderOutput(value, type) {
  lastOutput = value;
  outputBox.replaceChildren();
  const result = document.createElement('div');
  result.className = 'output-result';
  result.textContent = value || '(empty result)';
  outputBox.appendChild(result);
  outputType.textContent = type;
  outputCount.textContent = `${value.length} CHARACTERS`;
  copyBtn.disabled = !value;
}
function validateKeys() {
  if (selectedMode !== 'dany' && !key1.value) throw new Error('Enter the required secret key.');
  if (selectedMode === 'yam' && !key2.value) throw new Error('YAM requires both keys. Enter the second key.');
}
modeButtons.forEach(button => button.addEventListener('click', () => {
  selectedMode = button.dataset.mode;
  refreshMode();
  setNotice(`${selectedMode.toUpperCase()} selected. JavaScript engine is ready.`, 'success');
}));
encryptBtn.addEventListener('click', () => { operation = 'encrypt'; refreshOperation(); });
decryptBtn.addEventListener('click', () => { operation = 'decrypt'; refreshOperation(); });
inputText.addEventListener('input', () => {
  charCount.textContent = `${inputText.value.length} CHARACTER${inputText.value.length === 1 ? '' : 'S'}`;
});
$('clearBtn').addEventListener('click', () => {
  inputText.value = '';
  charCount.textContent = '0 CHARACTERS';
  inputText.focus();
});
$('runBtn').addEventListener('click', () => {
  try {
    if (!inputText.value.length) throw new Error('Enter a message before running the operation.');
    validateKeys();

    if (operation === 'encrypt') {
      const inputBytes = encoder.encode(inputText.value);
      const encrypted = encryptBytes(inputBytes);
      renderOutput(toHex(encrypted), `${selectedMode.toUpperCase()} ENCRYPTED · HEX`);
      setNotice('Encryption completed successfully. Copy or save the Hex result.', 'success');
    } else {
      const encryptedBytes = fromHex(inputText.value);
      const decryptedBytes = decryptBytes(encryptedBytes);
      let plaintext;
      try {
        plaintext = decoder.decode(decryptedBytes);
      } catch {
        // The C++ program emits bytes; invalid UTF-8 may occur for arbitrary input.
        // Show a Hex representation instead of corrupting data or crashing.
        renderOutput(toHex(decryptedBytes), `${selectedMode.toUpperCase()} DECRYPTED · RAW HEX`);
        setNotice('Decryption ran, but the output is not valid UTF-8 text. Showing the recovered bytes as Hex.', 'error');
        return;
      }
      renderOutput(plaintext, `${selectedMode.toUpperCase()} DECRYPTED · TEXT`);
      setNotice('Decryption completed successfully.', 'success');
    }
  } catch (error) {
    setNotice(error.message || 'Something went wrong.', 'error');
  }
});
copyBtn.addEventListener('click', async () => {
  if (!lastOutput) return;
  try {
    await navigator.clipboard.writeText(lastOutput);
    setNotice('Output copied to clipboard.', 'success');
  } catch {
    setNotice('Clipboard access was blocked by your browser. Select and copy the output manually.', 'error');
  }
});
refreshMode();
refreshOperation();
