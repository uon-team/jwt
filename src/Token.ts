import { JwtHeader } from "./Header";
import { JwtPayload } from "./Payload";


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