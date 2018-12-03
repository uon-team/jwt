

export interface JwtPayload {
    
    /**
     * Subject, to whom this token belong
     */
    sub?: string | number;

    /**
     * Issued at unix time
     */
    iat?: number;

    /**
     * No before, not valid before date
     */
    nbf?: number;

    /**
     * Expires at date
     */
    exp?: number;

    /**
     * Unique id for this token
     */
    jti?: string;

    /**
     * Issuer
     */
    iss?: string;

    /**
     * Any othe value
     */
    [k: string]: any;
}