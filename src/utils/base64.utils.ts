
export function JsonBase64Encode(obj: any) {
    const json = JSON.stringify(obj);

    return Base64ToUrlEncoded(Buffer.from(json).toString('base64'));
}

export function JsonBase64Decode(str: string) {

    const decoded = Buffer.from(UrlEncodedToBase64(str), 'base64').toString('utf8');
    return JSON.parse(decoded);
}


export function Base64ToUrlEncoded(base64: string) {
    return base64
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
}

export function UrlEncodedToBase64(base64url: string) {
    base64url = base64url.toString();

    var padding = 4 - base64url.length % 4;
    if (padding !== 4) {
        for (var i = 0; i < padding; ++i) {
            base64url += '=';
        }
    }

    return base64url
        .replace(/\-/g, '+')
        .replace(/_/g, '/');
}
