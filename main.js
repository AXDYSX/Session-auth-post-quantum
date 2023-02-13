//import { KeyGen1024 } from 'crystals-kyber';
import {crystalsKyber} from './node_modules/crystals-kyber/index.js';
//import KeyGen1024 from 'crystals-kyber';

let test = crystalsKyber.KeyGen1024();
console.log(test)

// Fonction pour créer un jeton d'authentification
function createAuthToken(userId) {
    const crypto = window.crypto
    const secretKey = crypto.getRandomValues(new Uint8Array(32)); // Clé secrète aléatoire de 32 octets
    const data = userId + Date.now(); //Données à signer, obtenu par concaténation de l'ID utilisateur et de la date
    const dataArray = new TextEncoder().encode(data);  //Encode les données de data dans une liste d'unsigned int
    
    return crypto.subtle.sign( //Méthode sign de l'api subtle signe les données avec l'algorithme HMAC (Keyed-Hash Message Authentication Code) en utilisant l'algorithme de hachage SHA-256.
    {
        name: "HMAC",
        hash: { name: "SHA-256" },
    },
      secretKey,
      dataArray
    ).then(signature => {
      return Array.from(new Uint8Array(signature))
        .map(b => b.toString(16).padStart(2, "0"))
        .join(""); //Conversion en une chaine de caractères hexadécimaux
    });
}


// Fonction pour créer une session
async function createSession(userId) {
    const sessionId = Date.now();
    const authToken = await createAuthToken(userId);
    
    if(localStorage.getItem('sessionId')){ // Vérification si sessionId existe déjà et le supprime si c'est le cas
        localStorage.removeItem('sessionId');
    }
    if(localStorage.getItem('authToken')){ // Vérification si authToken existe déjà et le supprime si c'est le cas
        localStorage.removeItem('authToken');
    }
    localStorage.setItem('sessionId', sessionId); // Stocke sessionId et authToken dans le localStorage
    localStorage.setItem('authToken', authToken);
    
    return { sessionId, authToken };
}
  
// export default {createAuthToken,createSession};
