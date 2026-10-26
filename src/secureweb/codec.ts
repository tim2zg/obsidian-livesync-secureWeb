/**
 * SecureWeb — Bincode 1.3 Mini-Codec and Padding Utilities
 *
 * Implements byte-for-byte serialization compatibility with Rust `bincode 1.3`
 * for `HybridSealed` and the true-E2E v2 service envelope structs.
 */

export const PAD_BUCKETS = [1024, 4096, 16384] as const;
export const PAD_OVERHEAD = 8;

export interface HybridSealed {
    suite: number; // 0 = XWingDraft06
    kemOutput: Uint8Array;
    ciphertext: Uint8Array;
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

// ---------------------------------------------------------------------------
// True-E2E v2 (opaque router): RouteEnvelope + ServiceRequest/ServiceResponse
// Byte-for-byte compatibility with Rust `bincode 1.3` structs in `common`.
// Padded at the SEAL layer with the SWP1 bucket frame (`pad_to_bucket`),
// so these structs carry no padLen fields.
// ---------------------------------------------------------------------------

export const ROUTE_ENVELOPE_VERSION = 2;
export const SERVICE_ENVELOPE_VERSION = 1;

const SWP1_MAGIC = [0x53, 0x57, 0x50, 0x31] as const; // "SWP1"

export interface ServiceRequestEnvelope {
    version: number;
    method: string;
    pathAndQuery: string;
    headers: [string, string][];
    body: Uint8Array;
    auth: string | null;
}

export interface RouteEnvelopeV2 {
    version: number;
    targetService: string;
    senderDeviceId: string;
    sealedRequest: Uint8Array;
    replyPubkey: Uint8Array; // 1216 bytes
    nonce: Uint8Array; // 12 bytes
    sentAtUnix: number | bigint;
    ttlSeconds: number;
}

export interface ServiceResponseEnvelope {
    version: number;
    status: number;
    headers: [string, string][];
    body: Uint8Array;
}

/**
 * Frame a serialized plaintext into its SWP1 padding bucket:
 * [SWP1 magic (4)] [orig_len: u32 LE] [payload] [zero pad to bucket].
 * Mirrors Rust `common::pad_to_bucket`.
 */
export function padToBucketFrame(payload: Uint8Array): Uint8Array {
    const bucket = padBucketFor(payload.length);
    const out = new Uint8Array(bucket);
    out.set(SWP1_MAGIC, 0);
    new DataView(out.buffer).setUint32(4, payload.length, true);
    out.set(payload, PAD_OVERHEAD);
    return out;
}

/**
 * Recover the payload from an SWP1 frame. Throws on missing magic or an
 * inconsistent length (corruption / hostile input).
 */
export function unpadFrame(frame: Uint8Array): Uint8Array {
    if (frame.length < PAD_OVERHEAD) {
        throw new Error('unpadFrame: frame shorter than SWP1 overhead');
    }
    for (let i = 0; i < 4; i++) {
        if (frame[i] !== SWP1_MAGIC[i]) {
            throw new Error('unpadFrame: missing SWP1 magic');
        }
    }
    const len = new DataView(frame.buffer, frame.byteOffset, frame.byteLength).getUint32(4, true);
    if (len > frame.length - PAD_OVERHEAD) {
        throw new Error('unpadFrame: inconsistent payload length');
    }
    return frame.subarray(PAD_OVERHEAD, PAD_OVERHEAD + len);
}

export function serializeServiceRequest(req: ServiceRequestEnvelope): Uint8Array {
    const w = new BincodeWriter();
    w.writeU8(req.version);
    w.writeString(req.method);
    w.writeString(req.pathAndQuery);
    w.writeU64(req.headers.length);
    for (const [k, v] of req.headers) {
        w.writeString(k);
        w.writeString(v);
    }
    w.writeVector(req.body);
    if (req.auth === null || req.auth === undefined) {
        w.writeU8(0);
    } else {
        w.writeU8(1);
        w.writeString(req.auth);
    }
    return w.getBytes();
}

export function deserializeServiceRequest(bytes: Uint8Array): ServiceRequestEnvelope {
    const r = new BincodeReader(bytes);
    const version = r.readU8();
    const method = r.readString();
    const pathAndQuery = r.readString();
    const headersLen = Number(r.readU64());
    const headers: [string, string][] = [];
    for (let i = 0; i < headersLen; i++) {
        headers.push([r.readString(), r.readString()]);
    }
    const body = r.readVector();
    const authTag = r.readU8();
    const auth = authTag === 0 ? null : r.readString();
    return { version, method, pathAndQuery, headers, body, auth };
}

export function serializeRouteEnvelope(route: RouteEnvelopeV2): Uint8Array {
    const w = new BincodeWriter();
    w.writeU8(route.version);
    w.writeString(route.targetService);
    w.writeString(route.senderDeviceId);
    w.writeVector(route.sealedRequest);
    w.writeVector(route.replyPubkey);
    if (route.nonce.length !== 12) {
        throw new Error(`RouteEnvelope nonce must be 12 bytes, got ${route.nonce.length}`);
    }
    w.writeBytes(route.nonce);
    w.writeU64(route.sentAtUnix);
    w.writeU32(route.ttlSeconds);
    return w.getBytes();
}

export function deserializeRouteEnvelope(bytes: Uint8Array): RouteEnvelopeV2 {
    const r = new BincodeReader(bytes);
    const version = r.readU8();
    const targetService = r.readString();
    const senderDeviceId = r.readString();
    const sealedRequest = r.readVector();
    const replyPubkey = r.readVector();
    const nonce = r.readBytes(12);
    const sentAtUnix = Number(r.readU64());
    const ttlSeconds = r.readU32();
    return { version, targetService, senderDeviceId, sealedRequest, replyPubkey, nonce, sentAtUnix, ttlSeconds };
}

export function serializeServiceResponse(resp: ServiceResponseEnvelope): Uint8Array {
    const w = new BincodeWriter();
    w.writeU8(resp.version);
    w.writeU16(resp.status);
    w.writeU64(resp.headers.length);
    for (const [k, v] of resp.headers) {
        w.writeString(k);
        w.writeString(v);
    }
    w.writeVector(resp.body);
    return w.getBytes();
}

export function deserializeServiceResponse(bytes: Uint8Array): ServiceResponseEnvelope {
    const r = new BincodeReader(bytes);
    const version = r.readU8();
    const status = r.readU16();
    const headersLen = Number(r.readU64());
    const headers: [string, string][] = [];
    for (let i = 0; i < headersLen; i++) {
        headers.push([r.readString(), r.readString()]);
    }
    const body = r.readVector();
    return { version, status, headers, body };
}
