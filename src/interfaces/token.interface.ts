import { JwtHeader } from "./header.interface";
import { JwtPayload } from "./payload.interface";


export interface JwtToken {

    /**
     * Token header
     */
    header: JwtHeader;

    /**
     * Token payload
     */
    payload: JwtPayload;

    /**
     * Token signature
     */
    signature: Buffer;
    
}