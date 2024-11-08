(async () => {
    // User-provided RSA keys (PEM formatted)
    const publicKeyPem = '-----BEGIN PUBLIC KEY-----\n...your public key...\n-----END PUBLIC KEY-----';
    const privateKeyPem = '-----BEGIN PRIVATE KEY-----\n...your private key...\n-----END PRIVATE KEY-----';
    const publicKey = await importRSAKey(publicKeyPem, true);
    const privateKey = await importRSAKey(privateKeyPem, false);

    const plainText = 'Hello, World!';
    const rsaCipherText = await encryptRSAOAEP(plainText, publicKey);
    const rsaCipherTextString = btoa(String.fromCharCode(...new Uint8Array(rsaCipherText)));
    const decryptedTextRSA = await decryptRSAOAEP(rsaCipherTextString, privateKey);

    console.log('RSA-OAEP Encrypted:', rsaCipherTextString);
    console.log('RSA-OAEP Decrypted:', decryptedTextRSA);
})();

async function encryptRSAOAEP(plainText, publicKey) {
    const encoded = new TextEncoder().encode(plainText);
    const cipherText = await window.crypto.subtle.encrypt(
        {
            name: 'RSA-OAEP'
        },
        publicKey,
        encoded
    );
    return cipherText;
}

async function decryptRSAOAEP(cipherTextString, privateKey) {
    const cipherText = new Uint8Array(atob(cipherTextString).split('').map(char => char.charCodeAt(0)));
    const decrypted = await window.crypto.subtle.decrypt(
        {
            name: 'RSA-OAEP'
        },
        privateKey,
        cipherText
    );
    return new TextDecoder().decode(decrypted);
}

async function importRSAKey(pem, isPublic = true) {
    const binaryDer = str2ab(pemToDer(pem));
    return window.crypto.subtle.importKey(
        isPublic ? 'spki' : 'pkcs8',
        binaryDer,
        {
            name: 'RSA-OAEP',
            hash: 'SHA-256'
        },
        true,
        isPublic ? ['encrypt'] : ['decrypt']
    );
}

function pemToDer(pem) {
    const b64 = pem.replace(/(-----(BEGIN|END) (PUBLIC|PRIVATE) KEY-----|\s)/g, '');
    return window.atob(b64);
}

function str2ab(str) {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0; i < str.length; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return buf;
}
