/**
 * SecureWeb — Bincode 1.3 Mini-Codec and Padding Utilities
 *
 * Implements byte-for-byte serialization compatibility with Rust `bincode 1.3`
 * for `HybridSealed`, `GatewayEnvelope`, and `GatewayHttpResponse`.
 */

export const PAD_BUCKETS = [1024, 4096, 16384] as const;
export const PAD_OVERHEAD = 8;
export const GATEWAY_ENVELOPE_VERSION = 1;

export interface HybridSealed {
    suite: number; // 0 = XWingDraft06
    kemOutput: Uint8Array;
    ciphertext: Uint8Array;
}

export interface GatewayEnvelope {
    version: number;
    senderDeviceId: string;
    targetHost: string;
    method: string;
    pathAndQuery: string;
    headers: [string, string][];
    body: Uint8Array;
    nonce: Uint8Array; // 12 bytes
    padLen: number; // u16
}

export interface GatewayHttpResponse {
    status: number; // u16
    headers: [string, string][];
    body: Uint8Array;
    padLen: number; // u16
}

/**
 * Select the smallest bucket >= rawLen + PAD_OVERHEAD, or round up to 16 KiB multiples.
 */
export function padBucketFor(rawLen: number): number {
    const minNeeded = rawLen + PAD_OVERHEAD;
    for (const bucket of PAD_BUCKETS) {
        if (minNeeded <= bucket) {
            return bucket;
        }
    }
    const maxBucket = PAD_BUCKETS[PAD_BUCKETS.length - 1];
    return Math.ceil(minNeeded / maxBucket) * maxBucket;
}

/**
 * Calculate the number of zero bytes to pad to reach the bucket boundary.
 */
export function calculatePadLen(rawLen: number): number {
    const bucket = padBucketFor(rawLen);
    return bucket - PAD_OVERHEAD - rawLen;
}

/**
 * Append padLen zero bytes to body.
 */
export function padBody(body: Uint8Array, padLen: number): Uint8Array {
    if (padLen <= 0) {
        return body;
    }
    const out = new Uint8Array(body.length + padLen);
    out.set(body, 0);
    return out;
}

/**
 * Strip padLen trailing bytes if they are all zero.
 */
export function unpadBody(body: Uint8Array, padLen: number): Uint8Array {
    if (padLen <= 0 || padLen >= body.length) {
        return body;
    }
    const cutoff = body.length - padLen;
    for (let i = cutoff; i < body.length; i++) {
        if (body[i] !== 0) {
            return body; // Non-zero detected; return unstripped
        }
    }
    return body.subarray(0, cutoff);
}

// ---------------------------------------------------------------------------
// Bincode 1.3 Binary Writer
// ---------------------------------------------------------------------------

export class BincodeWriter {
    private buffer: Uint8Array;
    private offset: number;

    constructor(initialCapacity = 2048) {
        this.buffer = new Uint8Array(initialCapacity);
        this.offset = 0;
    }

    private ensureCapacity(extraBytes: number) {
        const needed = this.offset + extraBytes;
        if (needed > this.buffer.length) {
            let newCap = this.buffer.length * 2;
            while (newCap < needed) {
                newCap *= 2;
            }
            const newBuf = new Uint8Array(newCap);
            newBuf.set(this.buffer);
            this.buffer = newBuf;
        }
    }

    writeU8(val: number) {
        this.ensureCapacity(1);
        this.buffer[this.offset++] = val & 0xff;
    }

    writeU16(val: number) {
        this.ensureCapacity(2);
        this.buffer[this.offset++] = val & 0xff;
        this.buffer[this.offset++] = (val >> 8) & 0xff;
    }

    writeU32(val: number) {
        this.ensureCapacity(4);
        this.buffer[this.offset++] = val & 0xff;
        this.buffer[this.offset++] = (val >> 8) & 0xff;
        this.buffer[this.offset++] = (val >> 16) & 0xff;
        this.buffer[this.offset++] = (val >> 24) & 0xff;
    }

    writeU64(val: number | bigint) {
        this.ensureCapacity(8);
        const b = typeof val === 'bigint' ? val : BigInt(val);
        const mask = BigInt(255);
        for (let i = 0; i < 8; i++) {
            this.buffer[this.offset++] = Number((b >> BigInt(i * 8)) & mask);
        }
    }

    writeBytes(bytes: Uint8Array) {
        this.ensureCapacity(bytes.length);
        this.buffer.set(bytes, this.offset);
        this.offset += bytes.length;
    }

    writeVector(bytes: Uint8Array) {
        this.writeU64(bytes.length);
        this.writeBytes(bytes);
    }

    writeString(str: string) {
        const encoded = new TextEncoder().encode(str);
        this.writeVector(encoded);
    }

    getBytes(): Uint8Array {
        return this.buffer.subarray(0, this.offset);
    }
}

// ---------------------------------------------------------------------------
// Bincode 1.3 Binary Reader
// ---------------------------------------------------------------------------

export class BincodeReader {
    private buffer: Uint8Array;
    private offset: number;

    constructor(buffer: Uint8Array) {
        this.buffer = buffer;
        this.offset = 0;
    }

    readU8(): number {
        if (this.offset + 1 > this.buffer.length) {
            throw new Error('BincodeReader: Unexpected end of buffer reading u8');
        }
        return this.buffer[this.offset++];
    }

    readU16(): number {
        if (this.offset + 2 > this.buffer.length) {
            throw new Error('BincodeReader: Unexpected end of buffer reading u16');
        }
        const b0 = this.buffer[this.offset++];
        const b1 = this.buffer[this.offset++];
        return b0 | (b1 << 8);
    }

    readU32(): number {
        if (this.offset + 4 > this.buffer.length) {
            throw new Error('BincodeReader: Unexpected end of buffer reading u32');
        }
        const b0 = this.buffer[this.offset++];
        const b1 = this.buffer[this.offset++];
        const b2 = this.buffer[this.offset++];
        const b3 = this.buffer[this.offset++];
        return (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) >>> 0;
    }

    readU64(): bigint {
        if (this.offset + 8 > this.buffer.length) {
            throw new Error('BincodeReader: Unexpected end of buffer reading u64');
        }
        let res = BigInt(0);
        for (let i = 0; i < 8; i++) {
            res |= BigInt(this.buffer[this.offset++]) << BigInt(i * 8);
        }
        return res;
    }

    readBytes(len: number): Uint8Array {
        if (this.offset + len > this.buffer.length) {
            throw new Error(`BincodeReader: Unexpected end of buffer reading ${len} bytes`);
        }
        const slice = this.buffer.subarray(this.offset, this.offset + len);
        this.offset += len;
        return slice;
    }

    readVector(): Uint8Array {
        const len = Number(this.readU64());
        return this.readBytes(len);
    }

    readString(): string {
        const bytes = this.readVector();
        return new TextDecoder().decode(bytes);
    }

    get remaining(): number {
        return this.buffer.length - this.offset;
    }
}

// ---------------------------------------------------------------------------
// Struct Serializers & Deserializers
// ---------------------------------------------------------------------------

export function serializeHybridSealed(sealed: HybridSealed): Uint8Array {
    const writer = new BincodeWriter();
    writer.writeU32(sealed.suite);
    writer.writeVector(sealed.kemOutput);
    writer.writeVector(sealed.ciphertext);
    return writer.getBytes();
}

export function deserializeHybridSealed(bytes: Uint8Array): HybridSealed {
    const reader = new BincodeReader(bytes);
    const suite = reader.readU32();
    const kemOutput = reader.readVector();
    const ciphertext = reader.readVector();
    return { suite, kemOutput, ciphertext };
}

export function serializeGatewayEnvelope(env: GatewayEnvelope): Uint8Array {
    const writer = new BincodeWriter();
    writer.writeU8(env.version);
    writer.writeString(env.senderDeviceId);
    writer.writeString(env.targetHost);
    writer.writeString(env.method);
    writer.writeString(env.pathAndQuery);

    // headers: Vec<(String, String)>
    writer.writeU64(env.headers.length);
    for (const [k, v] of env.headers) {
        writer.writeString(k);
        writer.writeString(v);
    }

    // body: Vec<u8> (already padded if padLen > 0)
    writer.writeVector(env.body);

    // nonce: [u8; 12]
    if (env.nonce.length !== 12) {
        throw new Error(`GatewayEnvelope nonce must be 12 bytes, got ${env.nonce.length}`);
    }
    writer.writeBytes(env.nonce);

    // pad_len: u16
    writer.writeU16(env.padLen);

    return writer.getBytes();
}

export function deserializeGatewayEnvelope(bytes: Uint8Array): GatewayEnvelope {
    const reader = new BincodeReader(bytes);
    const version = reader.readU8();
    const senderDeviceId = reader.readString();
    const targetHost = reader.readString();
    const method = reader.readString();
    const pathAndQuery = reader.readString();

    const headersLen = Number(reader.readU64());
    const headers: [string, string][] = [];
    for (let i = 0; i < headersLen; i++) {
        const k = reader.readString();
        const v = reader.readString();
        headers.push([k, v]);
    }

    const body = reader.readVector();
    const nonce = reader.readBytes(12);
    const padLen = reader.readU16();

    return {
        version,
        senderDeviceId,
        targetHost,
        method,
        pathAndQuery,
        headers,
        body,
        nonce,
        padLen,
    };
}

export function serializeGatewayHttpResponse(resp: GatewayHttpResponse): Uint8Array {
    const writer = new BincodeWriter();
    writer.writeU16(resp.status);

    writer.writeU64(resp.headers.length);
    for (const [k, v] of resp.headers) {
        writer.writeString(k);
        writer.writeString(v);
    }

    writer.writeVector(resp.body);
    writer.writeU16(resp.padLen);

    return writer.getBytes();
}

export function deserializeGatewayHttpResponse(bytes: Uint8Array): GatewayHttpResponse {
    const reader = new BincodeReader(bytes);
    const status = reader.readU16();

    const headersLen = Number(reader.readU64());
    const headers: [string, string][] = [];
    for (let i = 0; i < headersLen; i++) {
        const k = reader.readString();
        const v = reader.readString();
        headers.push([k, v]);
    }

    const body = reader.readVector();
    const padLen = reader.readU16();

    return {
        status,
        headers,
        body,
        padLen,
    };
}
