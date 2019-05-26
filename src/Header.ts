
export interface JwtHeader {
    /**
     * The algorithm
     */
    alg: string;

    /**
     * The token type, always JWT for now
     */
    typ: 'JWT';

    /**
     * other fields
     */
    [k: string]: string | number;
}