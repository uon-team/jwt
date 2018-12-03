

export interface VerifyOptions {


    /**
     * Force an algorithm to be used for verification.
     * It should be set to the same algorithm used by the encoding method.
     * It is strongly recommended that you use this to prevent verification attacks
     */
    alg?: string;


    /**
     * Verify that the "issued at" date is equal to this one
     */
    iat?: number;

    /**
     * Verify that the "not before" date is smaller than Date.now()
     */
    nbf?: boolean;

    /**
     * Verify that the expiration date is greater than Date.now()
     */
    exp?: boolean;

    /**
     * Verify that the token ID is equal to this one
     */
    jti?: string;

    /**
     * Verify that the issuer is equal to this one
     */
    iss?: string;

    /**
     * Verify subject is equal to this one
     */
    sub?: string | number


}


export interface VerifyResult {

    sig: boolean;
    iat?: boolean;
    nbf?: boolean;
    exp?: boolean;
    jti?: boolean;
    iss?: boolean;
    sub?: boolean;
}