import { MasterKeys, MasterKey } from './MasterKeys';
import { DerivedKeys } from './DerivedKeys';
import * as plainDataUtils from './PlainDataUtils';

const HMAC_POS_DATA = 0x008
const HMAC_POS_TAG = 0x1B4
const NFC3D_AMIIBO_SIZE = 540;

export { plainDataUtils };

export function loadMasterKeys(key: number[]): MasterKeys|null {
    let dataKey = readMasterKey(key, 0);
    let tagKey = readMasterKey(key, 80);

    if (dataKey.magicBytesSize > 16
        || tagKey.magicBytesSize > 16) {
            return null;
        }
    
    return new MasterKeys(dataKey, tagKey);
}


let cachedSubtleCrypto: SubtleCrypto | null = null;

function getSubtleCrypto(): SubtleCrypto {
    if (cachedSubtleCrypto) {
        return cachedSubtleCrypto;
    }

    const fromGlobalScope = getGlobalScopeSubtle();
    if (fromGlobalScope) {
        cachedSubtleCrypto = fromGlobalScope;
        return fromGlobalScope;
    }

    const fromNode = getNodeSubtle();
    if (fromNode) {
        cachedSubtleCrypto = fromNode;
        return fromNode;
    }

    throw new Error('Web Crypto API is not available in this environment.');
}

function getGlobalScopeSubtle(): SubtleCrypto | null {
    const scope: any = typeof globalThis !== 'undefined' ? globalThis
        : typeof self !== 'undefined' ? self
        : typeof window !== 'undefined' ? window
        : undefined;

    const availableCrypto: Crypto | undefined = scope && scope.crypto ? scope.crypto : undefined;

    if (availableCrypto && availableCrypto.subtle) {
        return availableCrypto.subtle;
    }

    return null;
}

function getNodeSubtle(): SubtleCrypto | null {
    if (!isNodeEnvironment()) {
        return null;
    }

    const requireFn = getNodeRequire();
    if (!requireFn) {
        return null;
    }

    const nodeCrypto = tryRequire(requireFn, 'node:crypto') ?? tryRequire(requireFn, 'crypto');
    const subtle = nodeCrypto && nodeCrypto.webcrypto && nodeCrypto.webcrypto.subtle
        ? nodeCrypto.webcrypto.subtle
        : null;

    return subtle;
}

type NodeRequireFn = (id: string) => any;

function getNodeRequire(): NodeRequireFn | null {
    try {
        const requireFn = (Function('return typeof require === "function" ? require : null;')() as NodeRequireFn | null);
        return requireFn;
    }
    catch (error) {
        return null;
    }
}

function tryRequire(requireFn: NodeRequireFn, id: string): any | null {
    try {
        return requireFn(id);
    }
    catch (error) {
        return null;
    }
}

function isNodeEnvironment(): boolean {
    const scope = typeof globalThis !== 'undefined' ? (globalThis as any) : undefined;
    const processCandidate = scope && typeof scope.process === 'object' ? scope.process : undefined;

    return !!(processCandidate && processCandidate.versions && typeof processCandidate.versions.node === 'string');
}


function readMasterKey(buffer: number[], offset: number): MasterKey {
    let hmacKey = [];
    let typeString = [];
    let rfu;
    let magicBytesSize;
    let magicBytes = [];
    let xorPad = [];

    let reader = new ArrayReader(buffer);

    for (let i = 0; i < 16; i++)
        hmacKey[i] = reader.readUInt8(offset + i);
    for (let i = 0; i < 14; i++)
        typeString[i] = reader.readInt8(offset + i + 16);
    rfu = reader.readUInt8(offset + 16 + 14);
    magicBytesSize = reader.readUInt8(offset + 16 + 14 + 1);
    for (let i = 0; i < 16; i++)
        magicBytes[i] = reader.readUInt8(offset + i + 16 + 14 + 1 + 1);
    for (let i = 0; i < 32; i++)
        xorPad[i] = reader.readUInt8(offset + i + 16 + 14 + 1 + 1 + 16);

    return {
        hmacKey,
        typeString,
        rfu,
        magicBytesSize,
        magicBytes,
        xorPad,
    }
}

class ArrayReader {
    private uint8: Uint8Array;
    private int8: Int8Array;
    constructor(buffer: number[]) {
        this.uint8 = new Uint8Array(buffer);
        this.int8 = new Int8Array(buffer);
    }

    readUInt8(index: number): number {
        return this.uint8[index];
    }

    readInt8(index: number): number {
        return this.int8[index];
    }
}

export async function unpack(amiiboKeys: MasterKeys, tag: number[]): Promise<{ unpacked: number[]; result: boolean }> {
    let unpacked = new Array(NFC3D_AMIIBO_SIZE).fill(0);
    let result = false;
    let internal = new Array(NFC3D_AMIIBO_SIZE).fill(0);
    let dataKeys = new DerivedKeys();
    let tagKeys = new DerivedKeys();

    // Convert format
    tagToInternal(tag, internal);

    // Generate keys
    await amiiboKeygen(amiiboKeys.data, internal, dataKeys);
    await amiiboKeygen(amiiboKeys.tag, internal, tagKeys);

    // Decrypt
    await amiiboCipher('decrypt', dataKeys, internal, unpacked);

    // Regenerate tag HMAC. Note: order matters, data HMAC depends on tag HMAC!
    await computeHmac(tagKeys.hmacKey, unpacked, 0x1D4, 0x34, unpacked, HMAC_POS_TAG);

    // Regenerate data HMAC
    await computeHmac(dataKeys.hmacKey, unpacked, 0x029, 0x1DF, unpacked, HMAC_POS_DATA);

    memcpy(unpacked, 0x208, tag, 0x208, 0x14);

    result = memcmp(unpacked, HMAC_POS_DATA, internal, HMAC_POS_DATA, 32) == 0 &&
        memcmp(unpacked, HMAC_POS_TAG, internal, HMAC_POS_TAG, 32) == 0;

    return {
        unpacked,
        result,
    }
}

export async function pack(amiiboKeys: MasterKeys, plain: number[]): Promise<number[]> {
    let packed = new Array(NFC3D_AMIIBO_SIZE).fill(0);
    let cipher = new Array(NFC3D_AMIIBO_SIZE).fill(0);
    let dataKeys = new DerivedKeys();
    let tagKeys = new DerivedKeys();

    // Generate keys
    await amiiboKeygen(amiiboKeys.tag, plain, tagKeys);
    await amiiboKeygen(amiiboKeys.data, plain, dataKeys);

    // Generated tag HMAC
    await computeHmac(tagKeys.hmacKey, plain, 0x1D4, 0x34, cipher, HMAC_POS_TAG);

    // Generate data HMAC
    let hmacBuffer = ([] as number[]).concat(
        plain.slice(0x029, 0x029 + 0x18B),
        cipher.slice(HMAC_POS_TAG, HMAC_POS_TAG + 0x20),
        plain.slice(0x1D4, 0x1D4 + 0x34));
    await computeHmac(dataKeys.hmacKey, hmacBuffer, 0, hmacBuffer.length, cipher, HMAC_POS_DATA);

    // Encrypt
    await amiiboCipher('encrypt', dataKeys, plain, cipher);

    // Convert back to hardware
    internalToTag(cipher, packed);

    memcpy(packed, 0x208, plain, 0x208, 0x14);

    return packed;
}

function memcmp(s1: any[], s1Offset: number, s2: any[], s2Offset: number, size: number): number {
    for (let i = 0; i < size; i++) {
        if (s1[s1Offset + i] !== s2[s2Offset + i]) {
            return s1[s1Offset + i] - s2[s2Offset + i];
        }
    }
    return 0;
}

function memcpy(destination: number[]|DerivedKeys|Uint8Array, destinationOffset: number, source: number[]|DerivedKeys|Uint8Array, sourceOffset: number, length: number) {
    const setDestinationByte = (dest: number[]|DerivedKeys|Uint8Array, index: number, value: number) => {
        if (dest instanceof DerivedKeys) {
            dest.setByte(index, value);
        }
        else {
            (dest as any)[index] = value;
        }
    };

    const getSourceByte = (src: number[]|DerivedKeys|Uint8Array, index: number) => {
        if (src instanceof DerivedKeys) {
            return src.getByte(index);
        }
        return (src as any)[index];
    };

    for (let i = 0; i < length; i++) {
        setDestinationByte(destination, destinationOffset + i, getSourceByte(source, sourceOffset + i));
    }
}

function memccpy(destination: any[], destinationOffset: number, source: any[], sourceOffset: number, character: any, length: number) {
    for (let i = 0; i < length; i++) {
        destination[destinationOffset + i] = source[sourceOffset + i];
        if (source[sourceOffset + i] == character) {
            return destinationOffset + i + 1;
        }
    }
    return null;
}

function memset(destination: any[], destinationOffset: number, data: any, length: number) {
    for (let i = 0; i < length; i++) {
        destination[destinationOffset + i] = data;
    }
}

async function amiiboKeygen(masterKey: MasterKey, internalDump: number[], derivedKeys: DerivedKeys) {
    let seed: number[] = [];

    amiiboCalcSeed(internalDump, seed);
    await keygen(masterKey, seed, derivedKeys);
}

function amiiboCalcSeed(internaldump: number[], seed: number[]) {
    memcpy(seed, 0x00, internaldump, 0x029, 0x02);
	memset(seed, 0x02, 0x00, 0x0E);
	memcpy(seed, 0x10, internaldump, 0x1D4, 0x08);
	memcpy(seed, 0x18, internaldump, 0x1D4, 0x08);
	memcpy(seed, 0x20, internaldump, 0x1E8, 0x20);
}

function tagToInternal(tag: number[], internal: number[]) {
	memcpy(internal, 0x000, tag, 0x008, 0x008);
	memcpy(internal, 0x008, tag, 0x080, 0x020);
	memcpy(internal, 0x028, tag, 0x010, 0x024);
	memcpy(internal, 0x04C, tag, 0x0A0, 0x168);
	memcpy(internal, 0x1B4, tag, 0x034, 0x020);
	memcpy(internal, 0x1D4, tag, 0x000, 0x008);
	memcpy(internal, 0x1DC, tag, 0x054, 0x02C);
}

function internalToTag(internal: number[], tag: number[]) {
	memcpy(tag, 0x008, internal, 0x000, 0x008);
	memcpy(tag, 0x080, internal, 0x008, 0x020);
	memcpy(tag, 0x010, internal, 0x028, 0x024);
	memcpy(tag, 0x0A0, internal, 0x04C, 0x168);
	memcpy(tag, 0x034, internal, 0x1B4, 0x020);
	memcpy(tag, 0x000, internal, 0x1D4, 0x008);
	memcpy(tag, 0x054, internal, 0x1DC, 0x02C);
}

async function keygen(baseKey: MasterKey, baseSeed: number[], derivedKeys: DerivedKeys) {
    let preparedSeed: number[] = [];
    keygenPrepareSeed(baseKey, baseSeed, preparedSeed);
    await drbgGenerateBytes(baseKey.hmacKey, preparedSeed, derivedKeys);
}

function keygenPrepareSeed(baseKey: MasterKey, baseSeed: number[], output: number[]) {
    // 1: Copy whole type string
    let outputOffset = <number>memccpy(output, 0, baseKey.typeString, 0, 0, 14);

    // 2: Append (16 - magicBytesSize) from the input seed
    let leadingSeedBytes = 16 - baseKey.magicBytesSize;
    memcpy(output, outputOffset, baseSeed, 0, leadingSeedBytes);
    outputOffset += leadingSeedBytes;

    // 3: Append all bytes from magicBytes
    memcpy(output, outputOffset, baseKey.magicBytes, 0, baseKey.magicBytesSize);
    outputOffset += baseKey.magicBytesSize;

    // 4: Append bytes 0x10-0x1F from input seed
    memcpy(output, outputOffset, baseSeed, 0x10, 16);
    outputOffset += 16;

    // 5: Xor last bytes 0x20-0x3F of input seed with AES XOR pad and append them
    for (let i = 0; i < 32; i++) {
        output[outputOffset + i] = baseSeed[i + 32] ^ baseKey.xorPad[i];
    }
    outputOffset += 32;

    return outputOffset;
}

async function drbgGenerateBytes(hmacKey: number[], seed: number[], output: DerivedKeys) {
    const DRBG_OUTPUT_SIZE = 32;
    let outputSize = 48;
    let outputOffset = 0;

    const subtle = getSubtleCrypto();
    const hmacImportParams: HmacImportParams = { name: 'HMAC', hash: 'SHA-256' };
    const cryptoKey = await subtle.importKey('raw', new Uint8Array(hmacKey), hmacImportParams, false, ['sign']);

    let iteration = 0;
    while (outputSize > 0) {
        const block = await drbgStep(subtle, cryptoKey, iteration, seed);
        iteration++;

        if (outputSize < DRBG_OUTPUT_SIZE) {
            memcpy(output, outputOffset, block, 0, outputSize);
            break;
        }

        memcpy(output, outputOffset, block, 0, DRBG_OUTPUT_SIZE);
        outputOffset += DRBG_OUTPUT_SIZE;
        outputSize -= DRBG_OUTPUT_SIZE;
    }
}

async function drbgStep(subtle: SubtleCrypto, key: CryptoKey, iteration: number, seed: number[]): Promise<number[]> {
    const iterationBytes = new Uint8Array([(iteration >> 8) & 0x0f, (iteration >> 0) & 0x0f]);
    const data = new Uint8Array(iterationBytes.length + seed.length);
    data.set(iterationBytes, 0);
    data.set(seed, iterationBytes.length);

    const digest = await subtle.sign('HMAC', key, data);
    return Array.from(new Uint8Array(digest));
}

async function amiiboCipher(mode: 'encrypt' | 'decrypt', keys: DerivedKeys, input: number[], output: number[]) {
    const subtle = getSubtleCrypto();
    const cryptoKey = await subtle.importKey('raw', new Uint8Array(keys.aesKey), { name: 'AES-CTR', length: 128 } as any, false, ['encrypt', 'decrypt']);
    const data = new Uint8Array(input).subarray(0x02C, 0x02C + 0x188);
    const algorithm = { name: 'AES-CTR', counter: new Uint8Array(keys.aesIV), length: 128 };
    const processedBuffer = mode === 'encrypt'
        ? await subtle.encrypt(algorithm, cryptoKey, data)
        : await subtle.decrypt(algorithm, cryptoKey, data);
    const processed = Array.from(new Uint8Array(processedBuffer));

    memcpy(output, 0x02C, processed, 0, 0x188);

    memcpy(output, 0, input, 0, 0x008);
    memcpy(output, 0x028, input, 0x028, 0x004);
    memcpy(output, 0x1D4, input, 0x1D4, 0x034);
}

async function computeHmac(hmacKey: number[], input: number[]|Uint8Array, inputOffset: number, inputLength: number, output: number[], outputOffset: number) {
    const subtle = getSubtleCrypto();
    const hmacImportParams: HmacImportParams = { name: 'HMAC', hash: 'SHA-256' };
    const cryptoKey = await subtle.importKey('raw', new Uint8Array(hmacKey), hmacImportParams, false, ['sign']);
    const slice = Array.isArray(input)
        ? input.slice(inputOffset, inputOffset + inputLength)
        : Array.from((input as Uint8Array).slice(inputOffset, inputOffset + inputLength));
    const data = new Uint8Array(slice);
    const digest = await subtle.sign('HMAC', cryptoKey, data);
    const result = Array.from(new Uint8Array(digest));
    memcpy(output, outputOffset, result, 0, result.length);
}
