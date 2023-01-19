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
export declare class Verifier {
    private debug;
    private publicKeys;
    private keysUrl;
    private userPoolId;
    private region;
    private expectedClaims;
    constructor(params: IVerifierParams, claims?: {});
    fetchKeys: () => Promise<IKey[]>;
    private getPublicKeys;
    verify(token: string): Promise<any>;
    forgetPublicKeys: () => void;
}
