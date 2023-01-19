import fetch from 'node-fetch';
import jose = require('node-jose');

export interface IVerifierParams {
  userPoolId: string;
  region: string;
  debug: boolean;
}

export interface IKey {
  alg: string;
  e: string;
  kid: string;
  kty: string;
  n: string;
  use: string;
}

export class Verifier {
  private debug: boolean;
  private publicKeys: IKey[] = [];
  private keysUrl: string;

  private userPoolId;
  private region;
  private expectedClaims: any;

  constructor(params: IVerifierParams, claims = {}) {
    this.debug = true;
    if (!params.userPoolId) {
      throw Error('userPoolId param is required');
    }
    if (!params.region) {
      throw Error('region param is required');
    }
    if (params.debug === false) {
      this.debug = false;
    }

    this.userPoolId = params.userPoolId;
    this.region = params.region;
    this.expectedClaims = claims;

    this.keysUrl =
      'https://cognito-idp.' + this.region + '.amazonaws.com/' + this.userPoolId + '/.well-known/jwks.json';
  }

  fetchKeys = async (): Promise<IKey[]> => {
    const publicKeysResponse = await fetch(this.keysUrl);
    const responseJson = await publicKeysResponse.json();
    return Promise.resolve(responseJson.keys);
  };

  // remember the keys for subsequent calls
  private getPublicKeys = async () => {
    // if (!this.publicKeys) {
    this.publicKeys = await this.fetchKeys();
    // }
    return this.publicKeys;
  };

  async verify(token: string) {
    try {
      if (!token) {
        throw Error('token undefined');
      }

      const sections = token.split('.');
      const header = JSON.parse(jose.util.base64url.decode(sections[0]).toString());
      const kid = header.kid;

      if (this.debug) {
        console.debug(`verify-cognito-token: key id for ${token} is ${kid}`);
      }

      const publicKeys = await this.getPublicKeys();

      if (this.debug) {
        console.debug(`verify-cognito-token: public keys are ${JSON.stringify(this.publicKeys)}`);
      }

      const myPublicKey = publicKeys.find((k) => k.kid === kid);

      if (this.debug) {
        console.debug(`verify-cognito-token: token public key is ${myPublicKey}`);
      }

      if (!myPublicKey) {
        throw Error('verify-cognito-token: Public key not found at ' + this.keysUrl);
      }

      const joseKey = await jose.JWK.asKey(myPublicKey);

      const verifiedToken = await jose.JWS.createVerify(joseKey).verify(token);

      const claims = JSON.parse(verifiedToken.payload.toString());

      if (!claims.iss.endsWith(this.userPoolId)) {
        throw Error('verify-cognito-token: iss claim does not match user pool ID');
      }

      const now = Math.floor(new Date().getTime() / 1000);
      if (now > claims.exp) throw Error('verify-cognito-token: Token is expired');

      if (this.expectedClaims.aud && claims.token_use === 'access' && this.debug) {
        // tslint:disable-next-line: no-console
        console.warn('verify-cognito-token: WARNING! Access tokens do not have an aud claim');
      }

      for (const claim in this.expectedClaims) {
        // check the expected strings using strict equality against the token's claims
        if (typeof this.expectedClaims[claim] !== 'undefined') {
          if (['string', 'boolean', 'number'].includes(typeof this.expectedClaims[claim])) {
            if (this.expectedClaims[claim] !== claims[claim]) {
              throw Error(`verify-cognito-token: expected claim "${claim}" to be ${this.expectedClaims[claim]} but was ${claims[claim]}`);
            }
          }

          // apply the expected claims that are Functions against the claims that were found on the token
          if (typeof this.expectedClaims[claim] === 'function') {
            if (!this.expectedClaims[claim].call(null, claims[claim])) {
              throw Error(`verify-cognito-token: expected claim "${claim}" does not match`);
            }
          }

          if (typeof this.expectedClaims[claim] === 'object') {
            throw Error(`verify-cognito-token: use a function with claim "${claim}"`);
          }
        }
      }
      return claims;
    } catch (e) {
      if (this.debug) {
        // tslint:disable-next-line: no-console
        console.log("verify-cognito-token: Error:", e);
      }
      return false;
    }
  }

  forgetPublicKeys = () => {
    this.publicKeys = [];
  }
}
