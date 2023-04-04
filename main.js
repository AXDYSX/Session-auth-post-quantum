
// https://github.com/tniessen/node-pqclean 1st repositories i found
const PQClean = require('pqclean');

const {
  publicKey,
  privateKey
} = await PQClean.kem.generateKeyPair('mceliece8192128');

const { key, encryptedKey } = await publicKey.generateKey();
console.log("Bob's key", Buffer.from(key).toString('hex'));

const receivedKey = await privateKey.decryptKey(encryptedKey);
console.log("Alice's key", Buffer.from(receivedKey).toString('hex'));
// end of test code of the first repositories

// https://github.com/antontutoveanu/crystals-kyber-javascript 2nd repositories i found
const kyber = require('crystals-kyber');

// To generate a public and private key pair (pk, sk)
let pk_sk = kyber.KeyGen768();
let pk = pk_sk[0];
let sk = pk_sk[1];

// To generate a random 256 bit symmetric key (ss) and its encapsulation (c)
let c_ss = kyber.Encrypt768(pk);
let c = c_ss[0];
let ss1 = c_ss[1];

// To decapsulate and obtain the same symmetric key
let ss2 = kyber.Decrypt768(c,sk);

// Test function with KATs
kyber.Test768();

// end of test code of the second repositories


function createAuthToken(userId) {
    const crypto = window.crypto
    const secretKey = crypto.getRandomValues(new Uint8Array(32));
    const data = userId + Date.now(); 
    const dataArray = new TextEncoder().encode(data);
    
    return crypto.subtle.sign( 
    {
        name: "HMAC",
        hash: { name: "SHA-256" },
    },
      secretKey,
      dataArray
    ).then(signature => {
      return Array.from(new Uint8Array(signature))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
    });
}


async function createSession(userId) {
    const sessionId = Date.now();
    const authToken = await createAuthToken(userId);
    
    if(localStorage.getItem('sessionId')){ 
        localStorage.removeItem('sessionId');
    }
    if(localStorage.getItem('authToken')){ 
        localStorage.removeItem('authToken');
    }
    localStorage.setItem('sessionId', sessionId); 
    localStorage.setItem('authToken', authToken);
    
    return { sessionId, authToken };
}


/*
1ère étape :
Page web. Backend qui créé un cookie contenant un token d'authentification lorsque l'utilisateur se connecte, 1ère version algo pré-quantique qui créée le token, 
2ème version algo post-quantique. Le but est de faire un benchmark afin de voir le temps supplémentaire afin d'obtenir le cookie d'un algo à un autre.

2ème étape : 
Lorsque la personne se déconnecte puis se reconnecte, refaire un benchmark du temps nécessaire à la reconnexion.


Support: Pour tester le fonctionnement au préalable, tout sera fait en localhost puis lorsque tout est OK, configuration d'une VM avec un serveur Apache 
(Windows/Linux osef) et ensuite benchmark via un wireshark pour voir la durée entre envoi et réception des données.
*/