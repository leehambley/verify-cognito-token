const fetch = require('node-fetch');
const jose = require('node-jose');

let publicKeys, keysUrl;

async function fetchKeys() {
  const publicKeysResponse = await fetch(keysUrl);
  const responseJson = await publicKeysResponse.json();
  return responseJson.keys;
}

//remember the keys for subsequent calls
async function getPublicKeys() {
  if (!publicKeys) {
    publicKeys = fetchKeys();
  }
  return publicKeys;
}

class Verifier {
  constructor(params, claims = {}) {
    if (!params.userPoolId) throw Error('userPoolId param is required');
    if (!params.region) throw Error('region param is required');

    this.userPoolId = params.userPoolId;
    this.region = params.region;
    this.expectedClaims = claims;

    keysUrl = 'https://cognito-idp.' + this.region + '.amazonaws.com/' + this.userPoolId + '/.well-known/jwks.json';
  }

  async verify(token) {
    try {
      const sections = token.split('.');
      const header = JSON.parse(jose.util.base64url.decode(sections[0]));
      const kid = header.kid;

      const publicKeys = await getPublicKeys();

      const myPublicKey = publicKeys.find(k => k.kid === kid);

      if (!myPublicKey) throw Error('Public key not found at ' + keysUrl);

      const joseKey = await jose.JWK.asKey(myPublicKey);

      const verifiedToken = await jose.JWS.createVerify(joseKey).verify(token);

      const claims = JSON.parse(verifiedToken.payload);

      if (!claims.iss.endsWith(this.userPoolId)) throw Error('iss claim does not match user pool ID');

      const now = Math.floor(new Date() / 1000);
      if (now > claims.exp) throw Error('Token is expired');

      if (this.expectedClaims.aud && claims.token_use === 'access') console.warn('WARNING! Access tokens do not have an aud claim');

      for (let claim in this.expectedClaims) {

        //check the expected strings using strict equality against the token's claims
        console.log(claim + ' is ', claims[claim]);
        if (typeof this.expectedClaims[claim] !== 'undefined') {
          if (['string', 'boolean', 'number'].includes(typeof this.expectedClaims[claim])) {
            
            if (this.expectedClaims[claim] !== claims[claim]) {
              throw Error(`expected claim "${claim}" to be ${this.expectedClaims[claim]} but was ${claims[claim]}`);
            }
          }

          //apply the expected claims that are Functions against the claims that were found on the token
          if (typeof this.expectedClaims[claim] === 'function') {
            console.log('### gonna call this', this.expectedClaims[claim], ' against this', claims[claim]);
            if(!this.expectedClaims[claim].call(null, claims[claim])){
              throw Error(`expected claim "${claim}" does not match`);
            }
          }

          if (typeof this.expectedClaims[claim] === 'object') {
            throw Error(`use a function with claim "${claim}"`);

          }
        }
      }

      return true;
    } catch (e) {
      console.log(e);
      return false;
    }
  }

  forgetPublicKeys() {
    publicKeys = null;
  }
}

module.exports = Verifier;