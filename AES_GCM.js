(async () => {
    // User-provided AES key and IV (initialization vector)
    const rawAESKey = new Uint8Array([..."11111111111111111111111111111111"]); // Replace with actual AES key bytes
    const aesIV = new Uint8Array([..."111111111111"]);     // Replace with actual IV bytes
    const aesKey = await importAESKey(rawAESKey);

    const plainText = 'Hello, World!';
    const aesCipherText = await encryptAESGCM(plainText, aesKey, aesIV);
    const aesCipherTextString = btoa(String.fromCharCode(...new Uint8Array(aesCipherText)));
    const decryptedTextAES = await decryptAESGCM(aesCipherTextString, aesKey, aesIV);
    
    console.log('AES-GCM Encrypted:', aesCipherTextString);
    console.log('AES-GCM Decrypted:', decryptedTextAES);
})();

async function encryptAESGCM(plainText, key, iv) {
    const encoded = new TextEncoder().encode(plainText);
    const cipherText = await window.crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv
        },
        key,
        encoded
    );
    return cipherText;
}

async function decryptAESGCM(cipherTextString, key, iv) {
    const cipherText = new Uint8Array(atob(cipherTextString).split('').map(char => char.charCodeAt(0)));
    const decrypted = await window.crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: iv
        },
        key,
        cipherText
    );
    return new TextDecoder().decode(decrypted);
}

async function importAESKey(rawKey) {
    return window.crypto.subtle.importKey(
        'raw',
        rawKey,
        {
            name: 'AES-GCM',
            length: 256
        },
        true,
        ['encrypt', 'decrypt']
    );
}
