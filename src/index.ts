import { JwtHeader } from "./Header";
import { JwtPayload } from "./Payload";
import { JwtToken } from "./Token";
import { VerifyOptions, VerifyResult, IsVerifyValid } from "./Verify";

import { IsValidAlgorithm, ALGORITHMS, Algorithms } from "./Algorithm";
import { UrlEncodedToBase64, JsonBase64Decode, Base64ToUrlEncoded, JsonBase64Encode } from "./Utils";

// default verify options, empty object
const DEFAULT_VERIFY_OPTIONS = {};


// re-export
export { JwtHeader, JwtPayload, JwtToken, VerifyOptions, VerifyResult, IsVerifyValid };

/**
 * Encode a token
 * @param payload 
 * @param key 
 * @param alg 
 */
export function Encode(payload: JwtPayload, key: string | Buffer, alg: string): string {

    // check provided algo against algo list
    if (!IsValidAlgorithm(alg)) {
        throw new Error(`Invalid algorithm, got ${alg}, must be one of ${ALGORITHMS}`);
    }

    // encode header in url-encoded base64
    const header_b64 = JsonBase64Encode({ alg, typ: 'JWT' });

    // encode payload in the same fashion
    const payload_b64 = JsonBase64Encode(payload);

    // concat the header and payload, this is what we are going to sign
    const unsigned = `${header_b64}.${payload_b64}`;

    // grab the sign/verify functions
    const signer = Algorithms[alg];

    // create a signature and url-encode it
    const sig = Base64ToUrlEncoded(signer.sign(unsigned, key));

    // append signature to header and payload
    return `${unsigned}.${sig}`;
}


/**
 * Decode a token
 * @param token 
 */
export function Decode(token: string): JwtToken {

    // split token in its parts
    const parts = token.split('.');

    // token must have 3 parts
    if (parts.length !== 3) {
        throw new Error(`Invalid token, must have 3 parts, got ${parts.length}`);
    }

    // decode header into an object
    const header: JwtHeader = JsonBase64Decode(parts[0]);

    // decode payload into an object
    const payload: JwtPayload = JsonBase64Decode(parts[1]);

    // decode signature into regular base64
    const signature: Buffer = Buffer.from(UrlEncodedToBase64(parts[2]), 'base64');

    // return the decoded token
    return { header, payload, signature };
}

/**
 * Verify a token
 * @param token 
 * @param key 
 * @param opts 
 */
export function Verify(token: string, key: string | Buffer, opts: VerifyOptions = DEFAULT_VERIFY_OPTIONS): VerifyResult {

    // decode token for access to its payload and header
    const decoded = Decode(token);
    const payload = decoded.payload
    const parts = token.split('.');

    const alg = opts.alg || decoded.header.alg;
    const now = Date.now();

    const verifier = Algorithms[alg];

    const result: VerifyResult = {};

    // verify signature
    if(opts.sig === undefined || opts.sig === true) {
        result.sig = verifier.verify(`${parts[0]}.${parts[1]}`, UrlEncodedToBase64(parts[2]), key);
    }

    // verify expiration
    if (opts.exp === true && payload.exp !== undefined) {
        result.exp = payload.exp > now;
    }

    // verify expiration
    if (opts.nbf === true && payload.nbf !== undefined) {
        result.nbf = payload.nbf <= now;
    }

    // verify issued at
    if (opts.iat !== undefined) {
        result.iat = payload.iat === opts.iat;
    }

    // verify issuer
    if (opts.iss !== undefined) {
        result.iss = payload.iss === opts.iss;
    }

    // verify token id
    if (opts.jti !== undefined) {
        result.jti = payload.jti !== opts.jti
    }

    // verify subject
    if (opts.sub !== undefined) {
        result.sub = payload.sub === opts.sub
    }

    // verify audience
    if (opts.aud !== undefined) {
        result.aud = payload.aud === opts.aud
    }

    return result;
}

