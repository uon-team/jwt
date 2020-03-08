
import * as crypto from 'crypto';
import { derToJose, joseToDer } from 'ecdsa-sig-formatter';

export const ALGORITHM_TYPES = [
    'HS256',
    'HS384',
    'HS512',
    'RS256',
    'RS384',
    'RS512',
    'ES256',
    'ES384',
    'ES512'
];

export function IsValidAlgorithm(alg: string) {
    return ALGORITHM_TYPES.indexOf(alg) > -1;
}

export interface IAlgorithm {
    sign(encoded: string, secret: string | Buffer): string;
    verify(encoded: string, signature: string, secret: string | Buffer): boolean;
}

export const ALGORITHMS: { [k: string]: IAlgorithm } = {

    HS256: CreateHmacAlg(256),
    HS384: CreateHmacAlg(384),
    HS512: CreateHmacAlg(512),
    RS256: CreateRsaAlg(256),
    RS384: CreateRsaAlg(384),
    RS512: CreateRsaAlg(512),
    ES256: CreateEcDsaAlg(256),
    ES384: CreateEcDsaAlg(384),
    ES512: CreateEcDsaAlg(512)
}



function CreateHmacAlg(bits: number): IAlgorithm {

    const sign = function sign(encoded: string, secret: string | Buffer): string {
        const sig = crypto.createHmac('sha' + bits, secret)
            .update(encoded)
            .digest('base64');
        return sig;
    };

    const verify = function verify(encoded: string, signature: string, secret: string | Buffer): boolean {

        const sig = sign(encoded, secret);

        return sig === signature; //Buffer.compare(Buffer.from(sig), Buffer.from(signature)) === 0;
    }

    return { sign, verify };

}


function CreateRsaAlg(bits: number): IAlgorithm {

    const sign = function sign(encoded: string, privateKey: string | Buffer): string {

        const sig = crypto.createSign('RSA-SHA' + bits)
            .update(encoded)
            .sign(privateKey.toString(), 'base64');
        return sig;
    };

    const verify = function verify(encoded: string, signature: string, publicKey: string | Buffer): boolean {

        const verifier = crypto.createVerify('RSA-SHA' + bits);
        verifier.update(encoded);
        return verifier.verify(publicKey, signature, 'base64');
    }

    return { sign, verify };

}

function CreateEcDsaAlg(bits: number) {


    const sign = function sign(encoded: string, privateKey: string | Buffer): string {

        const sig = crypto.createSign('RSA-SHA' + bits)
            .update(encoded)
            .sign({ key: privateKey.toString()}, 'base64');
        return derToJose(sig, 'ES' + bits);
    };

    const verify = function verify(encoded: string, signature: string, publicKey: string | Buffer): boolean {

        signature = joseToDer(signature, 'ES' + bits).toString('base64');

        const verifier = crypto.createVerify('RSA-SHA' + bits);
        verifier.update(encoded);

        return verifier.verify(publicKey, signature, 'base64');
    }

    return { sign, verify };

}