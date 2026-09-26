import { connect } from 'cloudflare:sockets';
import { createHash, createHmac, createCipheriv, createDecipheriv, timingSafeEqual, randomBytes } from 'node:crypto';
import { Buffer } from 'node:buffer';

const DEFAULT_CONFIG = Object.freeze({
    DEFAULT_UUID: '965ef141-21c6-4b93-bcbd-f22adfbcca85',
    DEFAULT_PROXY_IP: '103.196.155.151:443',
    SS_METHOD: 'aes-128-gcm',
    UDP_RELAY_HOST: 'wsudprelay.up.railway.app',
    UDP_RELAY_PORT: 443,
    MAX_PROTOCOL_HEADER: 4096,
    MAX_TCP_PROXY_REPLAY: 4 * 1024 * 1024,
    REJECT_UDP_443: false,
    DNS_DOH_URL: 'https://cloudflare-dns.com/dns-query',
    DNS_DOH_TIMEOUT_MS: 5000,
    // URL RAW untuk update jarak jauh (bisa diisi URL GitHub Gist / Pastebin raw)
    REMOTE_CONFIG_URL: 'https://raw.githubusercontent.com/Ddfathu/cfwv2ray-mod/refs/heads/main/default-udp-proxy.json',
});

let RUNTIME_CONFIG = {
    UUID_LIST: [DEFAULT_CONFIG.DEFAULT_UUID],
    ACTIVE_UUID: DEFAULT_CONFIG.DEFAULT_UUID,
    DEFAULT_PROXY_IP: DEFAULT_CONFIG.DEFAULT_PROXY_IP,
    SS_METHOD: DEFAULT_CONFIG.SS_METHOD,
    UDP_RELAY_HOST: DEFAULT_CONFIG.UDP_RELAY_HOST,
    UDP_RELAY_PORT: DEFAULT_CONFIG.UDP_RELAY_PORT,
    DNS_DOH_URL: DEFAULT_CONFIG.DNS_DOH_URL,
    DNS_DOH_TIMEOUT_MS: DEFAULT_CONFIG.DNS_DOH_TIMEOUT_MS,
    REJECT_UDP_443: DEFAULT_CONFIG.REJECT_UDP_443,
    MAX_PROTOCOL_HEADER: DEFAULT_CONFIG.MAX_PROTOCOL_HEADER,
    MAX_TCP_PROXY_REPLAY: DEFAULT_CONFIG.MAX_TCP_PROXY_REPLAY,
};

let LAST_KV_SYNC = 0;
async function syncConfigFromKV(env, force = false) {
    if (!env || !env.KV) return;
    const now = Date.now();
    if (!force && now - LAST_KV_SYNC < 60000) return;
    try {
        const rawUuids = await env.KV.get('UUID_LIST');
        if (rawUuids) {
            const list = JSON.parse(rawUuids);
            if (Array.isArray(list) && list.length > 0) {
                RUNTIME_CONFIG.UUID_LIST = list;
                RUNTIME_CONFIG.ACTIVE_UUID = list[0];
            }
        }
        const proxyIp = await env.KV.get('DEFAULT_PROXY_IP');
        if (proxyIp !== null && proxyIp !== undefined) {
            RUNTIME_CONFIG.DEFAULT_PROXY_IP = proxyIp.trim();
        }

        const relayHost = await env.KV.get('UDP_RELAY_HOST');
        if (relayHost) RUNTIME_CONFIG.UDP_RELAY_HOST = relayHost;

        const relayPort = await env.KV.get('UDP_RELAY_PORT');
        if (relayPort) RUNTIME_CONFIG.UDP_RELAY_PORT = Number(relayPort);

        const dohUrl = await env.KV.get('DNS_DOH_URL');
        if (dohUrl) RUNTIME_CONFIG.DNS_DOH_URL = dohUrl;
        LAST_KV_SYNC = now;
    } catch (e) {
        console.error('KV Sync error:', e);
    }
}

// SINKRONISASI REMOTE CONFIG DARI URL RAW DENGAN AUTO-FALLBACK
let LAST_REMOTE_SYNC = 0;
async function syncRemoteConfig(force = false) {
    const rawUrl = String(DEFAULT_CONFIG.REMOTE_CONFIG_URL || '').trim();
    if (!rawUrl || rawUrl.includes('username/repo')) return;

    const now = Date.now();
    if (!force && now - LAST_REMOTE_SYNC < 60000) return;

    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 4000);
        const res = await fetch(rawUrl, {
            headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
            cf: { cacheTtl: 60 },
            signal: controller.signal
        });
        clearTimeout(timeout);

        if (res.ok) {
            const text = (await res.text()).trim();
            try {
                const data = JSON.parse(text);
                if (data.proxy_ip) RUNTIME_CONFIG.DEFAULT_PROXY_IP = String(data.proxy_ip).trim();
                if (data.udp_relay_host) RUNTIME_CONFIG.UDP_RELAY_HOST = String(data.udp_relay_host).trim();
                if (data.udp_relay_port) RUNTIME_CONFIG.UDP_RELAY_PORT = Number(data.udp_relay_port);
            } catch {
                // Mendukung teks mentah baris per baris (baris 1 = proxy_ip, baris 2 = relay_host:port)
                const lines = text.split('\n').map(l => l.trim()).filter(Boolean);
                if (lines[0]) RUNTIME_CONFIG.DEFAULT_PROXY_IP = lines[0];
                if (lines[1]) {
                    const [h, p] = lines[1].split(':');
                    RUNTIME_CONFIG.UDP_RELAY_HOST = h;
                    if (p) RUNTIME_CONFIG.UDP_RELAY_PORT = Number(p);
                }
            }
            LAST_REMOTE_SYNC = now;
        }
    } catch (e) {
        // Fallback otomatis tetap memakai konfigurasi bawaan/KV jika fetch gagal
        console.error('Remote config fetch fallback:', e?.message || e);
    }
}

const ATYP_IPV4 = 0x01;
const ATYP_DOMAIN = 0x02;
const ATYP_IPV6 = 0x03;
const CMD_TCP = 0x01;
const CMD_UDP = 0x02;
const CMD_MUX = 0x03;
const CMD_RVS = 0x04;
const MUX_STATUS_NEW = 0x01;
const MUX_STATUS_KEEP = 0x02;
const MUX_STATUS_END = 0x03;
const MUX_STATUS_KEEPALIVE = 0x04;
const MUX_OPTION_DATA = 0x01;
const MUX_OPTION_ERROR = 0x02;
const MUX_NETWORK_TCP = 0x01;
const MUX_NETWORK_UDP = 0x02;
const MAX_MUX_META_LEN = 512;
const MAX_MUX_DATA_LEN = 65535;
const VMESS_VERSION = 1;
const VMESS_SECURITY_AUTO = 2;
const VMESS_SECURITY_AES128_GCM = 3;
const VMESS_SECURITY_CHACHA20_POLY1305 = 4;
const VMESS_SECURITY_NONE = 5;
const VMESS_SECURITY_ZERO = 6;
const VMESS_OPT_CHUNK_STREAM = 0x01;
const VMESS_OPT_CONNECTION_REUSE = 0x02;
const VMESS_OPT_CHUNK_MASKING = 0x04;
const VMESS_OPT_GLOBAL_PADDING = 0x08;
const VMESS_OPT_AUTHENTICATED_LENGTH = 0x10;
const VMESS_CMD_KEY_SALT = 'c48619fe-8f02-49e0-b9e9-edf763e17e21';
const KDF_ROOT = utf8('VMess AEAD KDF');
const KDF_AUTH_ID = utf8('AES Auth ID Encryption');
const KDF_HDR_LEN_KEY = utf8('VMess Header AEAD Key_Length');
const KDF_HDR_LEN_IV = utf8('VMess Header AEAD Nonce_Length');
const KDF_HDR_KEY = utf8('VMess Header AEAD Key');
const KDF_HDR_IV = utf8('VMess Header AEAD Nonce');
const KDF_RESP_LEN_KEY = utf8('AEAD Resp Header Len Key');
const KDF_RESP_LEN_IV = utf8('AEAD Resp Header Len IV');
const KDF_RESP_KEY = utf8('AEAD Resp Header Key');
const KDF_RESP_IV = utf8('AEAD Resp Header IV');
const KDF_AUTH_LEN = utf8('auth_len');
const CRC32_TABLE = (() => {
    const t = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
        let c = i;
        for (let j = 0; j < 8; j++) {
            c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
        }
        t[i] = c >>> 0;
    }
    return t;
})();

function utf8(text) { return new TextEncoder().encode(String(text)); }
function concatBytes(...parts) {
    const list = parts.filter((p) => p && p.byteLength !== 0).map(toU8Sync);
    const total = list.reduce((n, p) => n + p.byteLength, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const p of list) {
        out.set(p, off);
        off += p.byteLength;
    }
    return out;
}
function toU8Sync(value) {
    if (value instanceof Uint8Array) return value;
    if (value instanceof ArrayBuffer) return new Uint8Array(value);
    if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    if (Buffer.isBuffer(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    throw new TypeError('expected binary data');
}
function bytesToHex(bytes) { return Buffer.from(toU8Sync(bytes)).toString('hex'); }
function normalizeUUID(text) {
    const s = String(text || '').trim().toLowerCase();
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(s)) {
        return s;
    }
    return s;
}
function uuidToBytes(text) {
    const s = String(text || '').trim().toLowerCase();
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(s)) {
        return new Uint8Array(Buffer.from(s.replaceAll('-', ''), 'hex'));
    }
    return md5(utf8(s));
}
function processVlessUUID(bytes) {
    const out = toU8Sync(bytes).slice();
    if (out.byteLength !== 16) throw new Error('VLESS UUID must be 16 bytes');
    out[6] = 0;
    out[7] = 0;
    return out;
}
function secureEqual(a, b) {
    const aa = Buffer.from(toU8Sync(a));
    const bb = Buffer.from(toU8Sync(b));
    return aa.length === bb.length && timingSafeEqual(aa, bb);
}
function md5(data) { return new Uint8Array(createHash('md5').update(Buffer.from(toU8Sync(data))).digest()); }
function sha256(data) { return new Uint8Array(createHash('sha256').update(Buffer.from(toU8Sync(data))).digest()); }
function sha224Hex(text) { return createHash('sha224').update(String(text), 'utf8').digest('hex'); }
function crc32(bytes) {
    let c = 0xffffffff;
    for (const b of toU8Sync(bytes)) c = CRC32_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
}
function fnv1a32(bytes) {
    let h = 0x811c9dc5;
    for (const b of toU8Sync(bytes)) {
        h ^= b;
        h = Math.imul(h, 0x01000193) >>> 0;
    }
    return h >>> 0;
}
function hmacSha256(key, data) {
    return new Uint8Array(createHmac('sha256', Buffer.from(toU8Sync(key))).update(Buffer.from(toU8Sync(data))).digest());
}
function hmacWithHash(hashFn, key, data) {
    let k = toU8Sync(key);
    if (k.byteLength > 64) k = hashFn(k);
    const kb = new Uint8Array(64);
    kb.set(k);
    const ipad = new Uint8Array(64);
    const opad = new Uint8Array(64);
    for (let i = 0; i < 64; i++) {
        ipad[i] = kb[i] ^ 0x36;
        opad[i] = kb[i] ^ 0x5c;
    }
    return hashFn(concatBytes(opad, hashFn(concatBytes(ipad, data))));
}
function vmessKdf(key, ...pathParts) {
    let hashFn = (data) => hmacSha256(KDF_ROOT, data);
    for (const p of pathParts) {
        const prev = hashFn;
        const path = typeof p === 'string' ? utf8(p) : toU8Sync(p).slice();
        hashFn = (data) => hmacWithHash(prev, path, data);
    }
    return hashFn(toU8Sync(key));
}
function vmessKdf16(key, ...pathParts) { return vmessKdf(key, ...pathParts).slice(0, 16); }
function vmessCmdKey(uuidBytes) { return md5(concatBytes(uuidBytes, utf8(VMESS_CMD_KEY_SALT))); }

function cipherAeadName(security) {
    if (security === VMESS_SECURITY_AES128_GCM) return 'aes-128-gcm';
    if (security === VMESS_SECURITY_CHACHA20_POLY1305) return 'chacha20-poly1305';
    throw new Error(`security ${security} is not AEAD`);
}
function chachaKey(key16) {
    const a = md5(key16);
    const b = md5(a);
    return concatBytes(a, b);
}
function normalizeAeadKey(security, key) {
    const k = toU8Sync(key);
    return security === VMESS_SECURITY_CHACHA20_POLY1305 ? chachaKey(k) : k.slice(0, 16);
}
function aeadSeal(security, key, nonce, plain, aad = null) {
    const name = cipherAeadName(security);
    const cipher = createCipheriv(name, Buffer.from(normalizeAeadKey(security, key)), Buffer.from(toU8Sync(nonce)), { authTagLength: 16 });
    if (aad && toU8Sync(aad).byteLength) cipher.setAAD(Buffer.from(toU8Sync(aad)), { plaintextLength: toU8Sync(plain).byteLength });
    const c = Buffer.concat([cipher.update(Buffer.from(toU8Sync(plain))), cipher.final()]);
    return concatBytes(c, cipher.getAuthTag());
}
function aeadOpen(security, key, nonce, sealed, aad = null) {
    const input = toU8Sync(sealed);
    if (input.byteLength < 16) throw new Error('AEAD ciphertext too short');
    const name = cipherAeadName(security);
    const body = input.subarray(0, input.byteLength - 16);
    const tag = input.subarray(input.byteLength - 16);
    const decipher = createDecipheriv(name, Buffer.from(normalizeAeadKey(security, key)), Buffer.from(toU8Sync(nonce)), { authTagLength: 16 });
    if (aad && toU8Sync(aad).byteLength) decipher.setAAD(Buffer.from(toU8Sync(aad)), { plaintextLength: body.byteLength });
    decipher.setAuthTag(Buffer.from(tag));
    return new Uint8Array(Buffer.concat([decipher.update(Buffer.from(body)), decipher.final()]));
}
function aesEcbDecryptBlock(key, block) {
    const decipher = createDecipheriv('aes-128-cbc', Buffer.from(toU8Sync(key)), Buffer.alloc(16));
    decipher.setAutoPadding(false);
    return new Uint8Array(Buffer.concat([decipher.update(Buffer.from(toU8Sync(block))), decipher.final()]));
}

function parseRelayEndpoint(bytes, offset = 0) {
    const b = toU8Sync(bytes);
    if (b.byteLength < offset + 3) return null;
    const port = (b[offset] << 8) | b[offset + 1];
    const atyp = b[offset + 2];
    let p = offset + 3;
    if (port === 0) throw new Error('zero endpoint port');
    if (atyp === ATYP_IPV4) {
        if (b.byteLength < p + 4) return null;
        return { address: Array.from(b.subarray(p, p + 4)).join('.'), port, addressType: atyp, next: p + 4 };
    }
    if (atyp === ATYP_DOMAIN) {
        if (b.byteLength < p + 1) return null;
        const len = b[p++];
        if (!len || b.byteLength < p + len) return null;
        return { address: new TextDecoder('utf-8', { fatal: true }).decode(b.subarray(p, p + len)), port, addressType: atyp, next: p + len };
    }
    if (atyp === ATYP_IPV6) {
        if (b.byteLength < p + 16) return null;
        return { address: ipv6FromBytes(b.subarray(p, p + 16)), port, addressType: atyp, next: p + 16 };
    }
    throw new Error(`invalid endpoint address type ${atyp}`);
}

function encodeRelayEndpoint(endpoint) {
    const port = Number(endpoint.port);
    const head = new Uint8Array([(port >>> 8) & 0xff, port & 0xff]);
    const type = endpoint.addressType || inferAddressType(endpoint.address);
    if (type === ATYP_IPV4) return concatBytes(head, new Uint8Array([ATYP_IPV4]), ipv4ToBytes(endpoint.address));
    if (type === ATYP_IPV6) return concatBytes(head, new Uint8Array([ATYP_IPV6]), ipv6ToBytes(endpoint.address));
    const d = utf8(endpoint.address);
    return concatBytes(head, new Uint8Array([ATYP_DOMAIN, d.byteLength]), d);
}

class MuxFrameDecoder {
    constructor(maxMetaLen = MAX_MUX_META_LEN, maxDataLen = MAX_MUX_DATA_LEN) {
        this.maxMetaLen = maxMetaLen;
        this.maxDataLen = maxDataLen;
        this.pending = new Uint8Array(0);
    }
    push(chunk) {
        const input = toU8Sync(chunk);
        if (input.byteLength) this.pending = concatBytes(this.pending, input);
        const out = [];
        while (this.pending.byteLength >= 2) {
            const metaLen = (this.pending[0] << 8) | this.pending[1];
            if (metaLen < 4 || metaLen > this.maxMetaLen) throw new Error(`invalid Mux metadata length ${metaLen}`);
            const metaEnd = 2 + metaLen;
            if (this.pending.byteLength < metaEnd) break;
            const meta = this.pending.subarray(2, metaEnd);
            const option = meta[3];
            let total = metaEnd;
            let data = new Uint8Array(0);
            if ((option & MUX_OPTION_DATA) !== 0) {
                if (this.pending.byteLength < total + 2) break;
                const dataLen = (this.pending[total] << 8) | this.pending[total + 1];
                if (this.pending.byteLength < total + 2 + dataLen) break;
                data = this.pending.slice(total + 2, total + 2 + dataLen);
                total += 2 + dataLen;
            }
            const frame = parseMuxMetadata(meta, data);
            frame.raw = this.pending.slice(0, total);
            out.push(frame);
            this.pending = this.pending.slice(total);
        }
        return out;
    }
}

function parseMuxMetadata(metaBytes, data = new Uint8Array(0)) {
    const meta = toU8Sync(metaBytes);
    const frame = {
        id: (meta[0] << 8) | meta[1],
        status: meta[2],
        option: meta[3],
        network: 0,
        target: null,
        globalID: null,
        data: toU8Sync(data).slice(),
        raw: null,
    };
    let cursor = 4;
    if (frame.status === MUX_STATUS_NEW) {
        frame.network = meta[cursor++];
        const endpoint = parseRelayEndpoint(meta, cursor);
        if (!endpoint) throw new Error('truncated Mux New destination');
        frame.target = endpoint;
        cursor = endpoint.next;
        if (frame.network === MUX_NETWORK_UDP && meta.byteLength - cursor >= 8) {
            const gid = meta.slice(cursor, cursor + 8);
            if (gid.some(v => v !== 0)) frame.globalID = gid;
            cursor += 8;
        }
    } else if (frame.status === MUX_STATUS_KEEP) {
        if (meta.byteLength > cursor) {
            frame.network = meta[cursor++];
            const endpoint = parseRelayEndpoint(meta, cursor);
            if (!endpoint) throw new Error('truncated Mux UDP destination');
            frame.target = endpoint;
            cursor = endpoint.next;
        }
    }
    return frame;
}

function encodeMuxMeta(metaBytes) {
    const meta = toU8Sync(metaBytes);
    return concatBytes(new Uint8Array([meta.byteLength >>> 8, meta.byteLength & 0xff]), meta);
}
function encodeMuxPacket(metaBytes, data) {
    const meta = toU8Sync(metaBytes);
    const payload = toU8Sync(data);
    return concatBytes(encodeMuxMeta(meta), new Uint8Array([payload.byteLength >>> 8, payload.byteLength & 0xff]), payload);
}
function encodeMuxTcpData(id, data) {
    const meta = new Uint8Array([id >>> 8, id & 0xff, MUX_STATUS_KEEP, MUX_OPTION_DATA]);
    return encodeMuxPacket(meta, data);
}
function encodeMuxUdpData(id, endpoint, data) {
    const meta = concatBytes(new Uint8Array([id >>> 8, id & 0xff, MUX_STATUS_KEEP, MUX_OPTION_DATA, MUX_NETWORK_UDP]), encodeRelayEndpoint(endpoint));
    return encodeMuxPacket(meta, data);
}
function encodeMuxEnd(id, hasError = false) {
    return encodeMuxMeta(new Uint8Array([id >>> 8, id & 0xff, MUX_STATUS_END, hasError ? MUX_OPTION_ERROR : 0]));
}

function inferAddressType(address) {
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(String(address))) return ATYP_IPV4;
    if (String(address).includes(':')) return ATYP_IPV6;
    return ATYP_DOMAIN;
}
function parseProxyAddress(value) {
    const text = String(value || '').trim();
    if (!text) return null;
    const bracket = text.match(/^\[([^\]]+)](?::|=|-)(\d+)$/);
    const generic = bracket ? null : text.match(/^(.+?)(?::|=|-)(\d+)$/);
    const hostname = bracket ? bracket[1] : generic?.[1];
    const port = Number(bracket ? bracket[2] : generic?.[2]);
    if (!hostname || !Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error(`invalid proxy address ${value}`);
    }
    return { hostname, port };
}

// PARSER PATH DINAMIS:
// Format UDP Relay:  host=port atau ip=port (pemisah '=')
// Format Proxy IP:   host:port atau ip:port (pemisah ':')
function parseProtocolPath(pathname) {
    const clean = String(pathname || '').replace(/^\/+|\/+$/g, '');
    if (!clean) {
        return { protocol: 'auto', proxyAddress: '', udpRelay: null };
    }

    const parts = clean.split('/');
    let protocol = 'auto';
    let startIdx = 0;

    if (['vless', 'trojan', 'vmess', 'ss'].includes(parts[0].toLowerCase())) {
        protocol = parts[0].toLowerCase();
        startIdx = 1;
    }

    const remaining = parts.slice(startIdx);
    let udpRelay = null;
    let proxyAddress = '';

    for (const seg of remaining) {
        if (!seg) continue;
        if (seg.includes('=')) {
            try {
                const normalizedRelay = seg.replace('=', ':');
                parseProxyAddress(normalizedRelay);
                udpRelay = normalizedRelay;
            } catch {
                return null;
            }
        } else if (seg.includes(':')) {
            try {
                parseProxyAddress(seg);
                proxyAddress = seg;
            } catch {
                return null;
            }
        }
    }

    return { protocol, proxyAddress, udpRelay };
}

function ipv4ToBytes(address) { return new Uint8Array(String(address).split('.').map(Number)); }
function ipv6ToBytes(address) {
    let input = String(address).split('%')[0].toLowerCase();
    let ipv4Tail = null;
    const lastColon = input.lastIndexOf(':');
    if (input.includes('.') && lastColon >= 0) {
        const v4 = ipv4ToBytes(input.slice(lastColon + 1));
        ipv4Tail = [((v4[0] << 8) | v4[1]).toString(16), ((v4[2] << 8) | v4[3]).toString(16)];
        input = input.slice(0, lastColon) + ':' + ipv4Tail.join(':');
    }
    const halves = input.split('::');
    const left = halves[0] ? halves[0].split(':').filter(Boolean) : [];
    const right = halves[1] ? halves[1].split(':').filter(Boolean) : [];
    const words = [...left, ...Array(Math.max(0, 8 - left.length - right.length)).fill('0'), ...right];
    const out = new Uint8Array(16);
    words.forEach((w, i) => {
        const n = parseInt(w, 16);
        out[i * 2] = n >>> 8;
        out[i * 2 + 1] = n & 0xff;
    });
    return out;
}
function ipv6FromBytes(bytes) {
    const b = toU8Sync(bytes);
    const words = [];
    for (let i = 0; i < 16; i += 2) words.push(((b[i] << 8) | b[i + 1]).toString(16));
    return words.join(':');
}

function tryParsePortFirstAddress(bytes, cursor, addressType) {
    const b = toU8Sync(bytes);
    if (addressType === ATYP_IPV4) {
        if (b.byteLength < cursor + 4) return null;
        return { address: Array.from(b.subarray(cursor, cursor + 4)).join('.'), next: cursor + 4 };
    }
    if (addressType === ATYP_DOMAIN) {
        if (b.byteLength < cursor + 1) return null;
        const len = b[cursor++];
        if (!len || b.byteLength < cursor + len) return null;
        return { address: new TextDecoder('utf-8', { fatal: true }).decode(b.subarray(cursor, cursor + len)), next: cursor + len };
    }
    if (addressType === ATYP_IPV6) {
        if (b.byteLength < cursor + 16) return null;
        return { address: ipv6FromBytes(b.subarray(cursor, cursor + 16)), next: cursor + 16 };
    }
    throw new Error(`invalid address type ${addressType}`);
}

function tryParseVlessHeader(bytes) {
    const b = toU8Sync(bytes);
    if (b.byteLength < 18 || b[0] !== 0) return null;
    const user = b.slice(1, 17);
    const addonLength = b[17];
    const commandIndex = 18 + addonLength;
    if (b.byteLength < commandIndex + 1) return null;
    const command = b[commandIndex];
    if (command === CMD_MUX || command === CMD_RVS) {
        return { version: 0, user, addonLength, command, address: command === CMD_MUX ? 'v1.mux.cool' : 'v1.rvs.cool', port: 0, addressType: ATYP_DOMAIN, headerLength: commandIndex + 1 };
    }
    let p = commandIndex + 1;
    if (b.byteLength < p + 3) return null;
    const port = (b[p] << 8) | b[p + 1];
    p += 2;
    const addressType = b[p++];
    const a = tryParsePortFirstAddress(b, p, addressType);
    if (!a) return null;
    return { version: 0, user, addonLength, command, address: a.address, port, addressType, headerLength: a.next };
}

// Support UUID sembarang untuk VLESS
function isValidVlessUser(userBytes) {
    return true;
}

// Support password/hash sembarang untuk Trojan
function isValidTrojanHash(hashStr) {
    return true;
}

function tryParseSocksAddress(bytes, cursor) {
    const b = toU8Sync(bytes);
    if (b.byteLength < cursor + 1) return null;
    const atyp = b[cursor++];
    let address;
    if (atyp === 0x01) {
        if (b.byteLength < cursor + 6) return null;
        address = Array.from(b.subarray(cursor, cursor + 4)).join('.');
        cursor += 4;
    } else if (atyp === 0x03) {
        if (b.byteLength < cursor + 1) return null;
        const len = b[cursor++];
        if (!len || b.byteLength < cursor + len + 2) return null;
        address = new TextDecoder('utf-8', { fatal: true }).decode(b.subarray(cursor, cursor + len));
        cursor += len;
    } else if (atyp === 0x04) {
        if (b.byteLength < cursor + 18) return null;
        address = ipv6FromBytes(b.subarray(cursor, cursor + 16));
        cursor += 16;
    } else {
        throw new Error(`invalid Trojan address type ${atyp}`);
    }
    const port = (b[cursor] << 8) | b[cursor + 1];
    cursor += 2;
    return { address, port, addressType: atyp === 1 ? ATYP_IPV4 : atyp === 4 ? ATYP_IPV6 : ATYP_DOMAIN, next: cursor };
}

function encodeSocksAddress(endpoint) {
    const type = endpoint.addressType || inferAddressType(endpoint.address);
    let addr;
    if (type === ATYP_IPV4) addr = concatBytes(new Uint8Array([0x01]), ipv4ToBytes(endpoint.address));
    else if (type === ATYP_IPV6) addr = concatBytes(new Uint8Array([0x04]), ipv6ToBytes(endpoint.address));
    else {
        const d = utf8(endpoint.address);
        addr = concatBytes(new Uint8Array([0x03, d.byteLength]), d);
    }
    const port = Number(endpoint.port);
    return concatBytes(addr, new Uint8Array([(port >>> 8) & 0xff, port & 0xff]));
}

function tryParseTrojanHeader(bytes) {
    const b = toU8Sync(bytes);
    if (b.byteLength < 59) return null;
    const command = b[58];
    const ep = tryParseSocksAddress(b, 59);
    if (!ep || b.byteLength < ep.next + 2) return null;
    return { command: command === 0x01 ? CMD_TCP : CMD_UDP, address: ep.address, port: ep.port, addressType: ep.addressType, headerLength: ep.next + 2 };
}

class TrojanUdpDecoder {
    constructor() { this.pending = new Uint8Array(0); }
    push(chunk) {
        this.pending = concatBytes(this.pending, chunk);
        const out = [];
        while (this.pending.byteLength) {
            const ep = tryParseSocksAddress(this.pending, 0);
            if (!ep || this.pending.byteLength < ep.next + 4) break;
            const len = (this.pending[ep.next] << 8) | this.pending[ep.next + 1];
            const end = ep.next + 4 + len;
            if (this.pending.byteLength < end) break;
            out.push({ endpoint: { address: ep.address, port: ep.port, addressType: ep.addressType }, payload: this.pending.slice(ep.next + 4, end) });
            this.pending = this.pending.slice(end);
        }
        return out;
    }
}
function encodeTrojanUdpPacket(endpoint, payload) {
    const p = toU8Sync(payload);
    return concatBytes(encodeSocksAddress(endpoint), new Uint8Array([(p.byteLength >>> 8) & 0xff, p.byteLength & 0xff, 0x0d, 0x0a]), p);
}

class VmessReplayCache {
    constructor(ttlMs = 120000) { this.ttlMs = ttlMs; this.map = new Map(); }
    checkAndAdd(authId) {
        const now = Date.now();
        for (const [k, exp] of this.map) if (exp <= now) this.map.delete(k);
        const key = bytesToHex(authId);
        if (this.map.has(key)) return false;
        this.map.set(key, now + this.ttlMs);
        return true;
    }
}

function tryParseVmessHeaderMulti(bytes, uuidList, replayCache = null, nowSec = Math.floor(Date.now() / 1000)) {
    for (const u of uuidList) {
        try {
            const res = tryParseVmessHeader(bytes, uuidToBytes(u), replayCache, nowSec);
            if (res) return res;
        } catch { }
    }
    return null;
}

function tryParseVmessHeader(bytes, uuidBytes, replayCache = null, nowSec = Math.floor(Date.now() / 1000)) {
    const b = toU8Sync(bytes);
    if (b.byteLength < 16) return null;
    const cmdKey = vmessCmdKey(uuidBytes);
    const authID = b.slice(0, 16);
    let authPlain;
    try {
        authPlain = aesEcbDecryptBlock(vmessKdf16(cmdKey, KDF_AUTH_ID), authID);
    } catch {
        return null;
    }
    const dv = new DataView(authPlain.buffer, authPlain.byteOffset, authPlain.byteLength);
    const timestamp = Number(dv.getBigInt64(0, false));
    if (dv.getUint32(12, false) !== crc32(authPlain.subarray(0, 12)) || Math.abs(timestamp - nowSec) > 120) {
        return null;
    }
    if (b.byteLength < 42) return null;
    const encLen = b.subarray(16, 34);
    const connNonce = b.subarray(34, 42);
    let lengthPlain;
    try {
        lengthPlain = aeadOpen(VMESS_SECURITY_AES128_GCM, vmessKdf16(cmdKey, KDF_HDR_LEN_KEY, authID, connNonce), vmessKdf(cmdKey, KDF_HDR_LEN_IV, authID, connNonce).slice(0, 12), encLen, authID);
    } catch {
        return null;
    }
    const plainLen = (lengthPlain[0] << 8) | lengthPlain[1];
    const total = 42 + plainLen + 16;
    if (b.byteLength < total) return null;
    let plain;
    try {
        plain = aeadOpen(VMESS_SECURITY_AES128_GCM, vmessKdf16(cmdKey, KDF_HDR_KEY, authID, connNonce), vmessKdf(cmdKey, KDF_HDR_IV, authID, connNonce).slice(0, 12), b.subarray(42, total), authID);
    } catch {
        return null;
    }
    const requestBodyIV = plain.slice(1, 17);
    const requestBodyKey = plain.slice(17, 33);
    const responseHeader = plain[33];
    let option = plain[34];
    const wireSecurity = plain[35] & 0x0f;
    const command = plain[37];
    let security = wireSecurity;
    if (security === VMESS_SECURITY_ZERO) {
        security = VMESS_SECURITY_NONE;
        option &= ~(VMESS_OPT_CHUNK_STREAM | VMESS_OPT_CHUNK_MASKING | VMESS_OPT_GLOBAL_PADDING | VMESS_OPT_AUTHENTICATED_LENGTH);
    }
    let p = 38, address = 'v1.mux.cool', port = 0, addressType = ATYP_DOMAIN;
    if (command !== CMD_MUX) {
        port = (plain[p] << 8) | plain[p + 1];
        p += 2;
        addressType = plain[p++];
        const a = tryParsePortFirstAddress(plain, p, addressType);
        if (!a) throw new Error('truncated destination');
        address = a.address;
        p = a.next;
    }
    const checksumPos = plain.byteLength - 4;
    if (fnv1a32(plain.subarray(0, checksumPos)) !== new DataView(plain.buffer, plain.byteOffset + checksumPos, 4).getUint32(0, false)) {
        throw new Error('invalid VMess checksum');
    }
    if (replayCache && !replayCache.checkAndAdd(authID)) throw new Error('replayed VMess AuthID');
    return {
        command, address, port, addressType, option, security, wireSecurity,
        requestBodyIV, requestBodyKey, responseHeader, headerLength: total, authID,
        responseBodyKey: sha256(requestBodyKey).slice(0, 16),
        responseBodyIV: sha256(requestBodyIV).slice(0, 16),
    };
}

class NonceCounter {
    constructor(iv) { this.base = toU8Sync(iv).slice(); this.count = 0; }
    next(size = 12) {
        const out = this.base.slice();
        out[0] = (this.count >>> 8) & 0xff;
        out[1] = this.count & 0xff;
        this.count = (this.count + 1) & 0xffff;
        return out.slice(0, size);
    }
}

const KECCAK64_MASK = (1n << 64n) - 1n;
const KECCAK_ROTC = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];
const KECCAK_RC = [
    0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
    0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
    0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
    0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
    0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
    0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
function rotl64(value, shift) {
    const n = BigInt(shift & 63);
    return n === 0n ? (value & KECCAK64_MASK) : (((value << n) | (value >> (64n - n))) & KECCAK64_MASK);
}
function keccakF1600(state) {
    const c = new Array(5), d = new Array(5), b = new Array(25);
    for (const rc of KECCAK_RC) {
        for (let x = 0; x < 5; x++) c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        for (let x = 0; x < 5; x++) d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
        for (let y = 0; y < 5; y++) {
            for (let x = 0; x < 5; x++) state[x + 5 * y] = (state[x + 5 * y] ^ d[x]) & KECCAK64_MASK;
        }
        for (let y = 0; y < 5; y++) {
            for (let x = 0; x < 5; x++) {
                const src = x + 5 * y;
                b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(state[src], KECCAK_ROTC[src]);
            }
        }
        for (let y = 0; y < 5; y++) {
            const row = 5 * y;
            for (let x = 0; x < 5; x++) state[row + x] = (b[row + x] ^ ((~b[row + ((x + 1) % 5)]) & b[row + ((x + 2) % 5)])) & KECCAK64_MASK;
        }
        state[0] = (state[0] ^ rc) & KECCAK64_MASK;
    }
}

class Shake128Xof {
    constructor(input) {
        this.rate = 168;
        this.state = Array(25).fill(0n);
        this.squeezeOffset = 0;
        this.absorb(toU8Sync(input));
    }
    xorBlock(block) {
        for (let i = 0; i < block.byteLength; i++) {
            this.state[i >>> 3] ^= BigInt(block[i]) << BigInt((i & 7) * 8);
        }
    }
    absorb(input) {
        let offset = 0;
        while (input.byteLength - offset >= this.rate) {
            this.xorBlock(input.subarray(offset, offset + this.rate));
            keccakF1600(this.state);
            offset += this.rate;
        }
        const finalBlock = new Uint8Array(this.rate);
        finalBlock.set(input.subarray(offset));
        finalBlock[input.byteLength - offset] ^= 0x1f;
        finalBlock[this.rate - 1] ^= 0x80;
        this.xorBlock(finalBlock);
        keccakF1600(this.state);
    }
    read(length) {
        const out = new Uint8Array(length);
        for (let i = 0; i < length; i++) {
            if (this.squeezeOffset === this.rate) {
                keccakF1600(this.state);
                this.squeezeOffset = 0;
            }
            const p = this.squeezeOffset++;
            out[i] = Number((this.state[p >>> 3] >> BigInt((p & 7) * 8)) & 0xffn);
        }
        return out;
    }
}

class ShakeSizeParser {
    constructor(seed) { this.shake = new Shake128Xof(seed); }
    nextWord() {
        const b = this.shake.read(2);
        return (b[0] << 8) | b[1];
    }
    decodeSize(bytes) {
        const b = toU8Sync(bytes);
        return (((b[0] << 8) | b[1]) ^ this.nextWord()) & 0xffff;
    }
    encodeSize(size) {
        const v = (size ^ this.nextWord()) & 0xffff;
        return new Uint8Array([v >>> 8, v & 0xff]);
    }
    nextPaddingLen() { return this.nextWord() % 64; }
}

function randomPadding(n) { return n ? new Uint8Array(randomBytes(n)) : new Uint8Array(0); }

class VmessBodyDecoder {
    constructor(header) {
        this.header = header;
        this.pending = new Uint8Array(0);
        this.awaiting = null;
        this.done = false;
        this.transferType = header.command === CMD_UDP ? 'packet' : 'stream';
        this.zeroRaw = header.wireSecurity === VMESS_SECURITY_ZERO || (header.security === VMESS_SECURITY_NONE && !(header.option & VMESS_OPT_CHUNK_STREAM));
        this.sizeShake = (header.option & VMESS_OPT_CHUNK_MASKING) ? new ShakeSizeParser(header.requestBodyIV) : null;
        this.paddingShake = (header.option & VMESS_OPT_GLOBAL_PADDING) ? this.sizeShake : null;
        this.bodyNonce = new NonceCounter(header.requestBodyIV);
        this.lengthNonce = new NonceCounter(header.requestBodyIV);
        this.authLength = !!(header.option & VMESS_OPT_AUTHENTICATED_LENGTH) && [VMESS_SECURITY_AES128_GCM, VMESS_SECURITY_CHACHA20_POLY1305].includes(header.security);
        this.authLengthKey = this.authLength ? vmessKdf16(header.requestBodyKey, KDF_AUTH_LEN) : null;
    }
    push(chunk) {
        if (this.done) return [];
        const c = toU8Sync(chunk);
        if (this.zeroRaw) return c.byteLength ? [c.slice()] : [];
        this.pending = concatBytes(this.pending, c);
        const out = [];
        for (;;) {
            if (!this.awaiting) {
                const sizeBytes = this.authLength ? 18 : 2;
                if (this.pending.byteLength < sizeBytes) break;
                let padding = 0;
                if (this.paddingShake && (this.header.security !== VMESS_SECURITY_NONE || this.transferType === 'packet')) {
                    padding = this.paddingShake.nextPaddingLen();
                }
                let size;
                const raw = this.pending.slice(0, sizeBytes);
                if (this.authLength) {
                    const plain = aeadOpen(this.header.security, this.authLengthKey, this.lengthNonce.next(12), raw);
                    size = ((plain[0] << 8) | plain[1]) + 16;
                } else if (this.sizeShake) {
                    size = this.sizeShake.decodeSize(raw);
                } else {
                    size = (raw[0] << 8) | raw[1];
                }
                this.pending = this.pending.slice(sizeBytes);
                this.awaiting = { size, padding };
            }
            const { size, padding } = this.awaiting;
            if (this.pending.byteLength < size) break;
            const frame = this.pending.slice(0, size);
            this.pending = this.pending.slice(size);
            this.awaiting = null;
            if (this.header.security === VMESS_SECURITY_NONE) {
                if (this.transferType === 'stream') {
                    if (size === 0) { this.done = true; break; }
                    out.push(frame);
                } else {
                    if (size === padding) { this.done = true; break; }
                    out.push(frame.slice(0, size - padding));
                }
                continue;
            }
            if (size === 16 + padding) { this.done = true; break; }
            const sealed = frame.slice(0, size - padding);
            out.push(aeadOpen(this.header.security, this.header.requestBodyKey, this.bodyNonce.next(12), sealed));
        }
        return out;
    }
}

class VmessBodyEncoder {
    constructor(header) {
        this.header = header;
        this.responseKey = header.responseBodyKey;
        this.responseIV = header.responseBodyIV;
        this.transferType = header.command === CMD_UDP ? 'packet' : 'stream';
        this.zeroRaw = header.wireSecurity === VMESS_SECURITY_ZERO || (header.security === VMESS_SECURITY_NONE && !(header.option & VMESS_OPT_CHUNK_STREAM));
        this.sizeShake = (header.option & VMESS_OPT_CHUNK_MASKING) ? new ShakeSizeParser(this.responseIV) : null;
        this.paddingShake = (header.option & VMESS_OPT_GLOBAL_PADDING) ? this.sizeShake : null;
        this.bodyNonce = new NonceCounter(this.responseIV);
        this.lengthNonce = new NonceCounter(header.requestBodyIV);
        this.authLength = !!(header.option & VMESS_OPT_AUTHENTICATED_LENGTH) && [VMESS_SECURITY_AES128_GCM, VMESS_SECURITY_CHACHA20_POLY1305].includes(header.security);
        this.authLengthKey = this.authLength ? vmessKdf16(header.requestBodyKey, KDF_AUTH_LEN) : null;
    }
    encode(data) {
        const input = toU8Sync(data);
        if (this.zeroRaw) return input.slice();
        if (this.transferType === 'packet') return this.encodeUnit(input);
        const parts = [];
        for (let off = 0; off < input.byteLength; off += 8192) {
            parts.push(this.encodeUnit(input.slice(off, Math.min(input.byteLength, off + 8192))));
        }
        return concatBytes(...parts);
    }
    encodeUnit(plain) {
        const p = toU8Sync(plain);
        if (this.header.security === VMESS_SECURITY_NONE) {
            const size = p.byteLength;
            const sb = this.sizeShake ? this.sizeShake.encodeSize(size) : new Uint8Array([size >>> 8, size & 0xff]);
            return concatBytes(sb, p);
        }
        const padding = this.paddingShake ? this.paddingShake.nextPaddingLen() : 0;
        const sealed = aeadSeal(this.header.security, this.responseKey, this.bodyNonce.next(12), p);
        const size = sealed.byteLength + padding;
        let sb;
        if (this.authLength) {
            const plainSize = size - 16;
            sb = aeadSeal(this.header.security, this.authLengthKey, this.lengthNonce.next(12), new Uint8Array([plainSize >>> 8, plainSize & 0xff]));
        } else if (this.sizeShake) {
            sb = this.sizeShake.encodeSize(size);
        } else {
            sb = new Uint8Array([size >>> 8, size & 0xff]);
        }
        return concatBytes(sb, sealed, randomPadding(padding));
    }
}

function encodeVmessResponseHeader(header) {
    const plain = new Uint8Array([header.responseHeader, 0x00, 0x00, 0x00]);
    const lenPlain = new Uint8Array([0x00, plain.byteLength]);
    const lenKey = vmessKdf16(header.responseBodyKey, KDF_RESP_LEN_KEY);
    const lenIv = vmessKdf(header.responseBodyIV, KDF_RESP_LEN_IV).slice(0, 12);
    const payloadKey = vmessKdf16(header.responseBodyKey, KDF_RESP_KEY);
    const payloadIv = vmessKdf(header.responseBodyIV, KDF_RESP_IV).slice(0, 12);
    return concatBytes(aeadSeal(VMESS_SECURITY_AES128_GCM, lenKey, lenIv, lenPlain), aeadSeal(VMESS_SECURITY_AES128_GCM, payloadKey, payloadIv, plain));
}

const SS_LEGACY_MAX_CHUNK = 0x3fff;
function ssMethodSpec(method) {
    const m = String(method || '').trim().toLowerCase();
    const map = {
        'aes-128-gcm': { method: m, keySize: 16, saltSize: 16, aead: 'aes-128-gcm', nonceSize: 12, maxChunk: SS_LEGACY_MAX_CHUNK },
        'aes-256-gcm': { method: m, keySize: 32, saltSize: 32, aead: 'aes-256-gcm', nonceSize: 12, maxChunk: SS_LEGACY_MAX_CHUNK },
    };
    return map[m] || map['aes-128-gcm'];
}
function ssLegacyMasterKey(password, keySize) {
    const p = utf8(password);
    let prev = new Uint8Array(0), out = new Uint8Array(0);
    while (out.length < keySize) {
        prev = md5(concatBytes(prev, p));
        out = concatBytes(out, prev);
    }
    return out.slice(0, keySize);
}
function hmacSha1(key, data) { return new Uint8Array(createHmac('sha1', Buffer.from(key)).update(Buffer.from(data)).digest()); }
function hkdfSha1(secret, salt, info, length) {
    const prk = hmacSha1(salt, secret);
    let t = new Uint8Array(0), out = new Uint8Array(0), c = 1;
    while (out.length < length) {
        t = hmacSha1(prk, concatBytes(t, info, new Uint8Array([c++])));
        out = concatBytes(out, t);
    }
    return out.slice(0, length);
}
function ssLegacySessionKey(master, salt, keySize) { return hkdfSha1(master, toU8Sync(salt), utf8('ss-subkey'), keySize); }

function ssSeal(spec, key, nonce, plain) {
    const cipher = createCipheriv(spec.aead, Buffer.from(toU8Sync(key)), Buffer.from(toU8Sync(nonce)), { authTagLength: 16 });
    const body = Buffer.concat([cipher.update(Buffer.from(toU8Sync(plain))), cipher.final()]);
    return concatBytes(body, cipher.getAuthTag());
}
function ssOpen(spec, key, nonce, sealed) {
    const input = toU8Sync(sealed);
    if (input.length < 16) throw new Error('SS AEAD short');
    const body = input.slice(0, -16), tag = input.slice(-16);
    const d = createDecipheriv(spec.aead, Buffer.from(toU8Sync(key)), Buffer.from(toU8Sync(nonce)), { authTagLength: 16 });
    d.setAuthTag(Buffer.from(tag));
    return new Uint8Array(Buffer.concat([d.update(Buffer.from(body)), d.final()]));
}
function incNonce(n) {
    for (let i = 0; i < n.length; i++) {
        n[i] = (n[i] + 1) & 255;
        if (n[i]) break;
    }
}

class SsChunkDecoder {
    constructor(spec, sessionKey, nonce = null) {
        this.spec = spec;
        this.key = toU8Sync(sessionKey);
        this.nonce = nonce ? toU8Sync(nonce).slice() : new Uint8Array(spec.nonceSize);
        this.pending = new Uint8Array(0);
        this.want = -1;
    }
    push(data) {
        this.pending = concatBytes(this.pending, data);
        const out = [];
        for (;;) {
            if (this.want < 0) {
                if (this.pending.length < 18) break;
                const p = ssOpen(this.spec, this.key, this.nonce, this.pending.slice(0, 18));
                incNonce(this.nonce);
                this.pending = this.pending.slice(18);
                this.want = (p[0] << 8) | p[1];
            }
            if (this.pending.length < this.want + 16) break;
            const p = ssOpen(this.spec, this.key, this.nonce, this.pending.slice(0, this.want + 16));
            incNonce(this.nonce);
            this.pending = this.pending.slice(this.want + 16);
            this.want = -1;
            out.push(p);
        }
        return out;
    }
}
class SsChunkEncoder {
    constructor(spec, sessionKey, nonce = null) {
        this.spec = spec;
        this.key = toU8Sync(sessionKey);
        this.nonce = nonce ? toU8Sync(nonce).slice() : new Uint8Array(spec.nonceSize);
    }
    encode(data) {
        const p = toU8Sync(data);
        const parts = [];
        for (let o = 0; o < p.length; o += this.spec.maxChunk) {
            const chunk = p.slice(o, Math.min(p.length, o + this.spec.maxChunk));
            const l = new Uint8Array([chunk.length >>> 8, chunk.length & 255]);
            parts.push(ssSeal(this.spec, this.key, this.nonce, l));
            incNonce(this.nonce);
            parts.push(ssSeal(this.spec, this.key, this.nonce, chunk));
            incNonce(this.nonce);
        }
        return concatBytes(...parts);
    }
}

class SsLegacyServerCodec {
    constructor(method, password) {
        this.spec = ssMethodSpec(method);
        this.master = ssLegacyMasterKey(password, this.spec.keySize);
        this.pending = new Uint8Array(0);
        this.decoder = null;
        this.encoder = null;
    }
    push(data) {
        this.pending = concatBytes(this.pending, data);
        if (!this.decoder) {
            if (this.pending.length < this.spec.saltSize) return [];
            const salt = this.pending.slice(0, this.spec.saltSize);
            this.pending = this.pending.slice(this.spec.saltSize);
            this.decoder = new SsChunkDecoder(this.spec, ssLegacySessionKey(this.master, salt, this.spec.keySize));
        }
        const pending = this.pending;
        this.pending = new Uint8Array(0);
        return this.decoder.push(pending);
    }
    encode(data) {
        if (!this.encoder) {
            const salt = new Uint8Array(randomBytes(this.spec.saltSize));
            this.encoder = new SsChunkEncoder(this.spec, ssLegacySessionKey(this.master, salt, this.spec.keySize));
            return concatBytes(salt, this.encoder.encode(data));
        }
        return this.encoder.encode(data);
    }
}

function parseSsAddress(bytes, offset = 0) {
    const b = toU8Sync(bytes);
    if (b.length < offset + 1) return null;
    const type = b[offset++] & 0x0f;
    let address, addressType;
    if (type === 1) {
        if (b.length < offset + 6) return null;
        address = Array.from(b.slice(offset, offset + 4)).join('.');
        addressType = ATYP_IPV4;
        offset += 4;
    } else if (type === 3) {
        if (b.length < offset + 1) return null;
        const n = b[offset++];
        if (!n || b.length < offset + n + 2) return null;
        address = new TextDecoder().decode(b.slice(offset, offset + n));
        addressType = ATYP_DOMAIN;
        offset += n;
    } else if (type === 4) {
        if (b.length < offset + 18) return null;
        address = ipv6FromBytes(b.slice(offset, offset + 16));
        addressType = ATYP_IPV6;
        offset += 16;
    } else {
        throw new Error(`invalid SS address type ${type}`);
    }
    const port = (b[offset] << 8) | b[offset + 1];
    offset += 2;
    return { address, port, addressType, next: offset };
}

const WS_OPEN = 1;
const WS_CLOSING = 2;
const RELAY_MAGIC = new TextEncoder().encode('VLRLY004');
const RELAY_MODE_FIXED_UDP = 0x01;
const RELAY_MODE_MUX = 0x02;
const RELAY_MODE_PACKET_UDP = 0x03;
const VMESS_REPLAY = new VmessReplayCache();

function rejectUdpEndpoint(endpoint) {
    return Boolean(RUNTIME_CONFIG.REJECT_UDP_443 && Number(endpoint?.port) === 443);
}
function assertUdpEndpointAllowed(endpoint) {
    if (rejectUdpEndpoint(endpoint)) throw new Error('UDP/443 rejected');
}
function isDnsEndpoint(endpoint) { return Number(endpoint?.port) === 53; }

async function resolveDnsOverHttps(payload) {
    const query = toU8Sync(payload);
    const url = RUNTIME_CONFIG.DNS_DOH_URL;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), RUNTIME_CONFIG.DNS_DOH_TIMEOUT_MS);
    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/dns-message', 'Accept': 'application/dns-message' },
            body: query,
            signal: controller.signal,
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return new Uint8Array(await response.arrayBuffer());
    } finally {
        clearTimeout(timer);
    }
}

class LengthPrefixedPacketDecoder {
    constructor() { this.pending = new Uint8Array(0); }
    push(chunk) {
        const input = toU8Sync(chunk);
        if (input.byteLength) this.pending = concatBytes(this.pending, input);
        const out = [];
        for (;;) {
            if (this.pending.byteLength < 2) break;
            const length = (this.pending[0] << 8) | this.pending[1];
            if (this.pending.byteLength < 2 + length) break;
            out.push(this.pending.slice(2, 2 + length));
            this.pending = this.pending.slice(2 + length);
        }
        return out;
    }
}

class FixedDnsOverHttps {
    constructor(onPacket) {
        this.decoder = new LengthPrefixedPacketDecoder();
        this.onPacket = onPacket;
    }
    async writeRaw(bytes) {
        for (const packet of this.decoder.push(bytes)) {
            const answer = await resolveDnsOverHttps(packet);
            this.onPacket(answer);
        }
    }
}

class TcpBridge {
    constructor(proxyAddress, onData, onClose) {
        this.proxyAddress = (proxyAddress || RUNTIME_CONFIG.DEFAULT_PROXY_IP || '').trim();
        this.onData = onData;
        this.onClose = onClose;
        this.socket = null;
        this.writer = null;
        this.mode = null;
        this.received = false;
        this.replay = [];
        this.replayBytes = 0;
        this.fallbackPromise = null;
        this.closed = false;
        this.isDns = false;
        this.dns = null;
    }

    async open(address, port) {
        const portNum = Number(port);
        if (portNum === 53) {
            this.isDns = true;
            this.dns = new FixedDnsOverHttps((payload) => {
                this.onData(concatBytes(uint16be(payload.byteLength), payload));
            });
            return;
        }

        try {
            await this.openSocket(address, portNum, 'primary');
        } catch (error) {
            if (!this.proxyAddress) throw error;
            const target = parseProxyAddress(this.proxyAddress);
            this.mode = 'switching';
            await this.openSocket(target.hostname, target.port, 'fallback');
        }
    }

    async openSocket(address, port, mode) {
        const socket = connect({ hostname: address, port }, { allowHalfOpen: true, secureTransport: 'off' });
        try {
            await socket.opened;
        } catch (error) {
            try { socket.close(); } catch { }
            throw error;
        }
        this.socket = socket;
        this.writer = socket.writable.getWriter();
        this.mode = mode;
        void this.pump(socket, mode);
    }

    bufferReplay(bytes) {
        if (!this.proxyAddress || this.mode !== 'primary' || this.received) return false;
        if (this.replayBytes + bytes.byteLength > RUNTIME_CONFIG.MAX_TCP_PROXY_REPLAY) {
            throw new Error('TCP proxy replay buffer limit exceeded');
        }
        this.replay.push(bytes.slice());
        this.replayBytes += bytes.byteLength;
        return true;
    }

    clearReplay() {
        this.replay = [];
        this.replayBytes = 0;
    }

    async fallback() {
        if (!this.proxyAddress || this.mode === 'fallback') return;
        if (this.fallbackPromise) return this.fallbackPromise;

        this.fallbackPromise = (async () => {
            const target = parseProxyAddress(this.proxyAddress);
            const replay = this.replayBytes ? concatBytes(...this.replay) : null;
            this.clearReplay();
            const oldWriter = this.writer;
            const oldSocket = this.socket;
            this.writer = null;
            this.socket = null;
            this.mode = 'switching';
            try { oldWriter?.releaseLock(); } catch { }
            try { oldSocket?.close(); } catch { }
            await this.openSocket(target.hostname, target.port, 'fallback');
            if (replay?.byteLength) {
                await this.writer.write(replay);
            }
        })();

        try {
            await this.fallbackPromise;
        } finally {
            this.fallbackPromise = null;
        }
    }

    async write(bytes) {
        if (this.closed) return;
        if (this.isDns && this.dns) {
            await this.dns.writeRaw(bytes);
            return;
        }

        const b = toU8Sync(bytes);
        const buffered = this.bufferReplay(b);
        if (this.fallbackPromise) {
            await this.fallbackPromise;
            if (buffered) return;
        }

        if (!this.writer) throw new Error('TCP writer unavailable');
        try {
            await this.writer.write(b);
        } catch (error) {
            if (buffered && this.proxyAddress && this.mode !== 'fallback' && !this.received) {
                await this.fallback();
                return;
            }
            throw error;
        }
    }

    async pump(socket, mode) {
        const reader = socket.readable.getReader();
        let gotData = false;
        try {
            while (!this.closed && this.socket === socket) {
                const { value, done } = await reader.read();
                if (done) break;
                if (!value?.byteLength) continue;
                gotData = true;
                if (mode === 'primary') {
                    this.received = true;
                    this.clearReplay();
                }
                this.onData(toU8Sync(value));
            }
        } catch (error) {
            if (!this.closed && this.socket === socket) {
                console.error(`${mode} TCP read error:`, error?.message || error);
            }
        } finally {
            try { reader.releaseLock(); } catch { }
        }

        if (this.closed || this.socket !== socket) return;

        if (mode === 'primary' && !gotData && this.proxyAddress) {
            try {
                await this.fallback();
                return;
            } catch (error) {
                console.error('TCP fallback failed:', error?.message || error);
            }
        }

        this.close();
        this.onClose();
    }

    close() {
        if (this.closed) return;
        this.closed = true;
        try { this.writer?.releaseLock(); } catch { }
        try { this.socket?.close(); } catch { }
        this.writer = null;
        this.socket = null;
    }
}

class AutoSession {
    constructor(ws, proxyAddress, udpRelay) {
        this.ws = ws;
        this.proxyAddress = proxyAddress;
        this.udpRelay = udpRelay;
        this.buffer = new Uint8Array(0);
        this.actualSession = null;
        this.closed = false;
    }

    async ingest(chunk) {
        if (this.closed) return;
        if (this.actualSession) {
            await this.actualSession.ingest(chunk);
            return;
        }

        this.buffer = concatBytes(this.buffer, chunk);
        if (this.buffer.byteLength < 16) return;

        let detected = null;

        // 1. Cek VLESS: byte[0] == 0x00 & panjang >= 18
        if (this.buffer[0] === 0x00 && this.buffer.byteLength >= 18) {
            detected = 'vless';
        }

        // 2. Cek Trojan: byte 56, 57 adalah CRLF (\r\n)
        if (!detected && this.buffer.byteLength >= 58) {
            if (this.buffer[56] === 0x0d && this.buffer[57] === 0x0a) {
                detected = 'trojan';
            }
        }

        // 3. Cek VMess: authID decodable
        if (!detected && this.buffer.byteLength >= 42) {
            const vmessTest = tryParseVmessHeaderMulti(this.buffer, RUNTIME_CONFIG.UUID_LIST, null);
            if (vmessTest) {
                detected = 'vmess';
            }
        }

        // 4. Fallback Shadowsocks
        if (!detected && this.buffer.byteLength >= 50) {
            detected = 'ss';
        }

        if (detected) {
            this.actualSession = createProtocolSession(detected, this.ws, this.proxyAddress, this.udpRelay);
            const initialData = this.buffer;
            this.buffer = new Uint8Array(0);
            await this.actualSession.ingest(initialData);
        } else if (this.buffer.byteLength > 2048) {
            this.close();
        }
    }

    close() {
        this.closed = true;
        if (this.actualSession) this.actualSession.close();
        safeCloseWebSocket(this.ws);
    }
}

function createProtocolSession(protocol, transport, proxyAddress, udpRelay) {
    switch (protocol) {
        case 'auto': return new AutoSession(transport, proxyAddress, udpRelay);
        case 'vless': return new VlessSession(transport, proxyAddress, udpRelay);
        case 'trojan': return new TrojanSession(transport, proxyAddress, udpRelay);
        case 'vmess': return new VmessSession(transport, proxyAddress, udpRelay);
        case 'ss': return new ShadowsocksSession(transport, proxyAddress, udpRelay);
        default: throw new Error(`unsupported protocol ${protocol}`);
    }
}

function isWebSocketUpgrade(request) {
    const upgrade = request.headers.get('Upgrade');
    return Boolean(upgrade && upgrade.toLowerCase() === 'websocket');
}

export default {
    async fetch(request, env) {
        try {
            await syncConfigFromKV(env);
            await syncRemoteConfig(); // Ambil dari URL RAW jika diatur (fallback otomatis jika gagal)
            const url = new URL(request.url);

            if (url.pathname === '/api/settings') {
                if (request.method === 'POST') {
                    if (!env.KV) return new Response(JSON.stringify({ error: 'Binding KV belum dikonfigurasi!' }), { status: 400 });
                    const body = await request.json();

                    if (body.action === 'save_dns') {
                        if (body.DNS_DOH_URL) await env.KV.put('DNS_DOH_URL', String(body.DNS_DOH_URL));
                    } else if (body.action === 'save_udp') {
                        if (body.UDP_RELAY_HOST) await env.KV.put('UDP_RELAY_HOST', String(body.UDP_RELAY_HOST));
                        if (body.UDP_RELAY_PORT) await env.KV.put('UDP_RELAY_PORT', String(body.UDP_RELAY_PORT));
                    } else if (body.action === 'save_proxy_ip') {
                        const newProxy = String(body.DEFAULT_PROXY_IP || '').trim();
                        await env.KV.put('DEFAULT_PROXY_IP', newProxy);
                        RUNTIME_CONFIG.DEFAULT_PROXY_IP = newProxy;
                    } else if (body.action === 'add_uuid') {
                        const newUuid = normalizeUUID(body.uuid);
                        const list = [...RUNTIME_CONFIG.UUID_LIST];
                        if (!list.includes(newUuid)) {
                            list.push(newUuid);
                            await env.KV.put('UUID_LIST', JSON.stringify(list));
                        }
                    } else if (body.action === 'delete_uuid') {
                        const delUuid = normalizeUUID(body.uuid);
                        let list = RUNTIME_CONFIG.UUID_LIST.filter(u => u !== delUuid);
                        if (list.length === 0) list = [DEFAULT_CONFIG.DEFAULT_UUID];
                        await env.KV.put('UUID_LIST', JSON.stringify(list));
                    }

                    await syncConfigFromKV(env, true);
                    return new Response(JSON.stringify({ success: true, config: RUNTIME_CONFIG }), { headers: { 'Content-Type': 'application/json' } });
                }
                return new Response(JSON.stringify(RUNTIME_CONFIG), { headers: { 'Content-Type': 'application/json' } });
            }

            if ((url.pathname === '/' || url.pathname === '') && isWebSocketUpgrade(request)) {
                const route = { protocol: 'auto', proxyAddress: '', udpRelay: null };
                return handleWebSocket(request, route, url);
            }

            if (url.pathname === '/' || url.pathname === '') {
                return new Response(generateCleanUI(url.host, RUNTIME_CONFIG), {
                    status: 200,
                    headers: { 'Content-Type': 'text/html; charset=utf-8' }
                });
            }

            const route = parseProtocolPath(url.pathname);
            if (!route) return new Response('Not Found', { status: 404 });
            if (isWebSocketUpgrade(request)) return handleWebSocket(request, route, url);

            return new Response('Not Found', { status: 404 });
        } catch (error) {
            return new Response('Internal Server Error', { status: 500 });
        }
    },
};

async function handleWebSocket(request, route, url) {
    const pair = new WebSocketPair();
    const [client, ws] = Object.values(pair);
    ws.accept();
    const session = createProtocolSession(route.protocol, ws, route.proxyAddress, route.udpRelay);
    let chain = Promise.resolve();
    const enqueue = (data) => {
        chain = chain
            .then(async () => {
                if (session.closed) return;
                const bytes = await toUint8Array(data);
                await session.ingest(bytes);
            })
            .catch(() => {
                session.close();
            });
    };
    const earlyHeader = request.headers.get('Sec-WebSocket-Protocol') || '';
    const earlyLimit = parseEarlyDataLimit(url);
    const earlyData = earlyLimit > 0 ? decodeEarlyData(earlyHeader, earlyLimit) : null;
    if (earlyData?.byteLength) enqueue(earlyData);

    ws.addEventListener('message', (event) => enqueue(event.data));
    ws.addEventListener('close', () => chain.finally(() => session.close()));
    ws.addEventListener('error', () => session.close());

    const headers = new Headers();
    if (earlyData?.byteLength && earlyHeader) headers.set('Sec-WebSocket-Protocol', earlyHeader);
    return new Response(null, { status: 101, webSocket: client, headers });
}

class BaseSession {
    constructor(ws, proxyAddress, udpRelay) {
        this.ws = ws;
        this.proxyAddress = proxyAddress || '';
        this.udpRelay = udpRelay || null;
        this.closed = false;
        this.tcp = null;
        this.relay = null;
        this.muxRouter = null;
    }
    send(bytes) {
        if (this.closed || this.ws.readyState !== WS_OPEN) return;
        this.ws.send(toU8Sync(bytes));
    }
    close() {
        if (this.closed) return;
        this.closed = true;
        try { this.tcp?.close(); } catch { }
        try { this.relay?.close(); } catch { }
        try { this.muxRouter?.close(); } catch { }
        safeCloseWebSocket(this.ws);
    }
}

class VlessSession extends BaseSession {
    constructor(ws, proxyAddress, udpRelay) {
        super(ws, proxyAddress, udpRelay);
        this.pendingHeader = new Uint8Array(0);
        this.header = null;
        this.udpDecoder = null;
    }
    async ingest(chunk) {
        if (this.closed || !chunk.byteLength) return;
        if (!this.header) {
            this.pendingHeader = concatBytes(this.pendingHeader, chunk);
            const parsed = tryParseVlessHeader(this.pendingHeader);
            if (!parsed) return;
            if (!isValidVlessUser(parsed.user)) throw new Error('unauthorized VLESS UUID');
            this.header = parsed;
            const remainder = this.pendingHeader.slice(parsed.headerLength);
            this.pendingHeader = new Uint8Array(0);
            await this.openOutbound();
            this.send(new Uint8Array([0, 0]));
            if (remainder.byteLength) await this.writeOutbound(remainder);
            return;
        }
        await this.writeOutbound(chunk);
    }
    async openOutbound() {
        const h = this.header;
        if (h.command === CMD_TCP) {
            this.tcp = new TcpBridge(this.proxyAddress, (data) => this.send(data), () => this.close());
            await this.tcp.open(h.address, h.port);
            return;
        }
        if (h.command === CMD_UDP) {
            const endpoint = { address: h.address, port: h.port, addressType: h.addressType };
            assertUdpEndpointAllowed(endpoint);
            if (isDnsEndpoint(endpoint)) {
                this.dns = new FixedDnsOverHttps((payload) => this.send(concatBytes(uint16be(payload.byteLength), payload)));
                return;
            }
            this.udpDecoder = new LengthPrefixedPacketDecoder();
            this.relay = await RelayConnection.openFixedUDP(endpoint, this.udpRelay);
            this.relay.pumpFixedUDP((payload) => this.send(concatBytes(uint16be(payload.byteLength), payload)), () => this.close());
            return;
        }
        if (h.command === CMD_MUX) {
            this.muxRouter = new WorkerMuxRouter(this.proxyAddress, this.udpRelay, (data) => this.send(data));
            return;
        }
    }
    async writeOutbound(bytes) {
        if (this.header.command === CMD_TCP) return this.tcp.write(bytes);
        if (this.header.command === CMD_MUX) return this.muxRouter.ingest(bytes);
        if (this.dns) return this.dns.writeRaw(bytes);
        if (this.udpDecoder) {
            for (const packet of this.udpDecoder.push(bytes)) {
                await this.relay.writeFixedPacket(packet);
            }
        }
    }
}

class TrojanSession extends BaseSession {
    constructor(ws, proxyAddress, udpRelay) {
        super(ws, proxyAddress, udpRelay);
        this.pendingHeader = new Uint8Array(0);
        this.header = null;
        this.udpDecoder = null;
        this.mux = false;
    }
    async ingest(chunk) {
        if (this.closed || !chunk.byteLength) return;
        if (!this.header) {
            this.pendingHeader = concatBytes(this.pendingHeader, chunk);
            const parsed = tryParseTrojanHeader(this.pendingHeader);
            if (!parsed) return;
            this.header = parsed;
            const remainder = this.pendingHeader.slice(parsed.headerLength);
            this.pendingHeader = new Uint8Array(0);
            await this.openOutbound();
            if (remainder.byteLength) await this.writeOutbound(remainder);
            return;
        }
        await this.writeOutbound(chunk);
    }
    async openOutbound() {
        const h = this.header;
        if (h.command === CMD_TCP && h.address.toLowerCase() === 'v1.mux.cool') {
            this.mux = true;
            this.muxRouter = new WorkerMuxRouter(this.proxyAddress, this.udpRelay, (data) => this.send(data));
            return;
        }
        if (h.command === CMD_TCP) {
            this.tcp = new TcpBridge(this.proxyAddress, (data) => this.send(data), () => this.close());
            await this.tcp.open(h.address, h.port);
            return;
        }
        this.udpDecoder = new TrojanUdpDecoder();
    }
    async ensurePacketRelay() {
        if (this.relay && !this.relay.closed) return this.relay;
        this.relay = await RelayConnection.openPacketUDP(this.udpRelay);
        this.relay.pumpPacketUDP((endpoint, payload) => this.send(encodeTrojanUdpPacket(endpoint, payload)), () => { this.relay = null; });
        return this.relay;
    }
    async writeOutbound(bytes) {
        if (this.header.command === CMD_TCP) {
            return this.mux ? this.muxRouter.ingest(bytes) : this.tcp.write(bytes);
        }
        for (const packet of this.udpDecoder.push(bytes)) {
            if (rejectUdpEndpoint(packet.endpoint)) continue;
            if (isDnsEndpoint(packet.endpoint)) {
                const answer = await resolveDnsOverHttps(packet.payload);
                this.send(encodeTrojanUdpPacket(packet.endpoint, answer));
                continue;
            }
            const relay = await this.ensurePacketRelay();
            await relay.writePacket(packet.endpoint, packet.payload);
        }
    }
}

class ShadowsocksSession extends BaseSession {
    constructor(ws, proxyAddress, udpRelay) {
        super(ws, proxyAddress, udpRelay);
        this.spec = ssMethodSpec(RUNTIME_CONFIG.SS_METHOD);
        this.codec = new SsLegacyServerCodec(this.spec.method, RUNTIME_CONFIG.ACTIVE_UUID);
        this.header = null;
        this.plainPending = new Uint8Array(0);
    }
    sendEncrypted(bytes) {
        const encoded = this.codec.encode(bytes);
        if (encoded.byteLength) this.send(encoded);
    }
    async ingest(chunk) {
        if (this.closed || !chunk.byteLength) return;
        for (const plain of this.codec.push(chunk)) await this.consumePlain(plain);
    }
    async consumePlain(bytes) {
        if (!this.header) {
            this.plainPending = concatBytes(this.plainPending, bytes);
            const parsed = parseSsAddress(this.plainPending, 0);
            if (!parsed) return;
            this.header = parsed;
            const remainder = this.plainPending.slice(parsed.next);
            this.plainPending = new Uint8Array(0);
            this.tcp = new TcpBridge(this.proxyAddress, (data) => this.sendEncrypted(data), () => this.close());
            await this.tcp.open(this.header.address, this.header.port);
            if (remainder.byteLength) await this.tcp.write(remainder);
            return;
        }
        await this.tcp.write(bytes);
    }
}

class VmessSession extends BaseSession {
    constructor(ws, proxyAddress, udpRelay) {
        super(ws, proxyAddress, udpRelay);
        this.pendingHeader = new Uint8Array(0);
        this.header = null;
        this.decoder = null;
        this.encoder = null;
    }
    async ingest(chunk) {
        if (this.closed || !chunk.byteLength) return;
        if (!this.header) {
            this.pendingHeader = concatBytes(this.pendingHeader, chunk);
            const parsed = tryParseVmessHeaderMulti(this.pendingHeader, RUNTIME_CONFIG.UUID_LIST, VMESS_REPLAY);
            if (!parsed) return;
            this.header = parsed;
            const remainder = this.pendingHeader.slice(parsed.headerLength);
            this.pendingHeader = new Uint8Array(0);
            this.decoder = new VmessBodyDecoder(parsed);
            this.encoder = new VmessBodyEncoder(parsed);
            await this.openOutbound();
            this.send(encodeVmessResponseHeader(parsed));
            if (remainder.byteLength) await this.consumeBody(remainder);
            return;
        }
        await this.consumeBody(chunk);
    }
    async openOutbound() {
        const h = this.header;
        const onPlain = (data) => {
            const encoded = this.encoder.encode(data);
            if (encoded.byteLength) this.send(encoded);
        };
        if (h.command === CMD_TCP) {
            this.tcp = new TcpBridge(this.proxyAddress, onPlain, () => this.close());
            await this.tcp.open(h.address, h.port);
            return;
        }
        if (h.command === CMD_UDP) {
            const endpoint = { address: h.address, port: h.port, addressType: h.addressType };
            assertUdpEndpointAllowed(endpoint);
            if (isDnsEndpoint(endpoint)) {
                this.dnsPacket = async (payload) => onPlain(await resolveDnsOverHttps(payload));
                return;
            }
            this.relay = await RelayConnection.openFixedUDP(endpoint, this.udpRelay);
            this.relay.pumpFixedUDP((payload) => onPlain(payload), () => this.close());
            return;
        }
        if (h.command === CMD_MUX) {
            this.muxRouter = new WorkerMuxRouter(this.proxyAddress, this.udpRelay, onPlain);
            return;
        }
    }
    async consumeBody(bytes) {
        for (const plain of this.decoder.push(bytes)) {
            if (this.header.command === CMD_TCP) await this.tcp.write(plain);
            else if (this.header.command === CMD_UDP) {
                if (this.dnsPacket) await this.dnsPacket(plain);
                else await this.relay.writeFixedPacket(plain);
            } else {
                await this.muxRouter.ingest(plain);
            }
        }
    }
}

class WorkerMuxRouter {
    constructor(proxyAddress, udpRelay, onOutput) {
        this.proxyAddress = proxyAddress || '';
        this.udpRelay = udpRelay || null;
        this.onOutput = onOutput;
        this.decoder = new MuxFrameDecoder();
        this.sessions = new Map();
        this.closed = false;
        this.udpRelayConn = null;
    }
    emit(bytes) { if (!this.closed) this.onOutput(toU8Sync(bytes)); }
    async getPacketRelay() {
        if (this.udpRelayConn && !this.udpRelayConn.closed) return this.udpRelayConn;
        this.udpRelayConn = await RelayConnection.openPacketUDP(this.udpRelay);
        this.udpRelayConn.pumpPacketUDP((endpoint, payload) => {
            for (const [id, session] of this.sessions.entries()) {
                if (session.type === 'udp') {
                    this.emit(encodeMuxUdpData(id, endpoint, payload));
                    break;
                }
            }
        }, () => { this.udpRelayConn = null; });
        return this.udpRelayConn;
    }
    async ingest(bytes) {
        if (this.closed) return;
        for (const frame of this.decoder.push(bytes)) await this.handleFrame(frame);
    }
    async handleFrame(frame) {
        if (frame.status === MUX_STATUS_KEEPALIVE) return;

        if (frame.status === MUX_STATUS_NEW) {
            if (frame.network === MUX_NETWORK_TCP) {
                const tcp = new TcpBridge(this.proxyAddress, (data) => this.sendTcpData(frame.id, data), () => {
                    this.sessions.delete(frame.id);
                    this.emit(encodeMuxEnd(frame.id, false));
                });
                this.sessions.set(frame.id, { type: 'tcp', conn: tcp });
                await tcp.open(frame.target.address, frame.target.port);
                if (frame.data.byteLength) await tcp.write(frame.data);
                return;
            }

            if (frame.network === MUX_NETWORK_UDP) {
                this.sessions.set(frame.id, { type: 'udp', target: frame.target });
                if (frame.data.byteLength) {
                    await this.handleUdpFrame(frame.id, frame.target, frame.data);
                }
                return;
            }
        }

        if (frame.status === MUX_STATUS_KEEP && frame.data.byteLength) {
            const session = this.sessions.get(frame.id);
            if (!session) return;
            if (session.type === 'tcp') {
                await session.conn.write(frame.data);
            } else if (session.type === 'udp') {
                const target = frame.target || session.target;
                await this.handleUdpFrame(frame.id, target, frame.data);
            }
            return;
        }

        if (frame.status === MUX_STATUS_END) {
            const session = this.sessions.get(frame.id);
            if (session) {
                if (session.type === 'tcp') session.conn.close();
                this.sessions.delete(frame.id);
            }
        }
    }
    async handleUdpFrame(id, target, data) {
        if (!target || rejectUdpEndpoint(target)) return;
        if (isDnsEndpoint(target)) {
            const answer = await resolveDnsOverHttps(data);
            this.emit(encodeMuxUdpData(id, target, answer));
            return;
        }
        const relay = await this.getPacketRelay();
        await relay.writePacket(target, data);
    }
    sendTcpData(id, bytes) {
        const data = toU8Sync(bytes);
        for (let off = 0; off < data.byteLength; off += MAX_MUX_DATA_LEN) {
            this.emit(encodeMuxTcpData(id, data.subarray(off, Math.min(data.byteLength, off + MAX_MUX_DATA_LEN))));
        }
    }
    close() {
        this.closed = true;
        for (const s of this.sessions.values()) {
            if (s.type === 'tcp') s.conn.close();
        }
        this.sessions.clear();
        try { this.udpRelayConn?.close(); } catch { }
    }
}

class RelayConnection {
    constructor(ws, mode) {
        this.ws = ws;
        this.mode = mode;
        this.closed = false;
    }

    static async open(mode, endpoint = null, customRelay = null) {
        let host = '';
        let port = 443;

        if (customRelay) {
            try {
                const parsed = parseProxyAddress(customRelay);
                if (parsed) {
                    host = parsed.hostname;
                    port = parsed.port;
                }
            } catch { }
        }

        if (!host) {
            host = String(RUNTIME_CONFIG.UDP_RELAY_HOST || '').trim();
            port = Number(RUNTIME_CONFIG.UDP_RELAY_PORT) || 443;
        }

        if (!host || host === 'CHANGE_ME_TO_VPS_IP') throw new Error('UDP Relay not configured');

        const cleanHost = host.replace(/^https?:\/\//i, '').replace(/^wss?:\/\//i, '').replace(/\/+$/, '');
        const wsUrl = (port === 443 || port === 80) ? `https://${cleanHost}/` : `https://${cleanHost}:${port}/`;

        const resp = await fetch(wsUrl, {
            headers: { Upgrade: 'websocket' }
        });

        const ws = resp.webSocket;
        if (!ws) throw new Error('Failed to upgrade WebSocket to UDP relay');
        ws.accept();

        const relay = new RelayConnection(ws, mode);
        const parts = [RELAY_MAGIC, new Uint8Array([mode])];
        if (mode === RELAY_MODE_FIXED_UDP) parts.push(encodeRelayEndpoint(endpoint));

        await new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                cleanup();
                reject(new Error('Relay handshake timed out'));
            }, 7000);

            const onFirstMessage = (event) => {
                const b = toU8Sync(event.data);
                if (b.byteLength > 0 && b[0] === 0) {
                    cleanup();
                    resolve();
                } else {
                    cleanup();
                    reject(new Error('Relay rejected handshake'));
                }
            };

            const onError = (err) => { cleanup(); reject(err); };
            const onClose = () => { cleanup(); reject(new Error('Relay closed prematurely')); };

            function cleanup() {
                clearTimeout(timer);
                ws.removeEventListener('message', onFirstMessage);
                ws.removeEventListener('error', onError);
                ws.removeEventListener('close', onClose);
            }

            ws.addEventListener('message', onFirstMessage);
            ws.addEventListener('error', onError);
            ws.addEventListener('close', onClose);

            ws.send(concatBytes(...parts));
        });

        return relay;
    }

    static openFixedUDP(ep, customRelay = null) { return RelayConnection.open(RELAY_MODE_FIXED_UDP, ep, customRelay); }
    static openPacketUDP(customRelay = null) { return RelayConnection.open(RELAY_MODE_PACKET_UDP, null, customRelay); }

    async writeFixedPacket(payload) {
        if (this.closed || this.ws.readyState !== WS_OPEN) return;
        this.ws.send(concatBytes(uint16be(payload.byteLength), payload));
    }

    async writePacket(endpoint, payload) {
        if (this.closed || this.ws.readyState !== WS_OPEN) return;
        this.ws.send(concatBytes(encodeRelayEndpoint(endpoint), uint16be(payload.byteLength), payload));
    }

    async writeRaw(bytes) {
        if (this.closed || this.ws.readyState !== WS_OPEN) return;
        this.ws.send(toU8Sync(bytes));
    }

    pumpFixedUDP(onPacket, onClose) {
        const decoder = new LengthPrefixedPacketDecoder();
        this.ws.addEventListener('message', (event) => {
            const packets = decoder.push(toU8Sync(event.data));
            for (const pkt of packets) onPacket(pkt);
        });
        this.ws.addEventListener('close', () => { this.close(); onClose(); });
        this.ws.addEventListener('error', () => { this.close(); onClose(); });
    }

    pumpPacketUDP(onPacket, onClose) {
        let pending = new Uint8Array(0);
        this.ws.addEventListener('message', (event) => {
            pending = concatBytes(pending, toU8Sync(event.data));
            while (pending.byteLength) {
                const ep = parseRelayEndpoint(pending, 0);
                if (!ep || pending.byteLength < ep.next + 2) break;
                const len = (pending[ep.next] << 8) | pending[ep.next + 1];
                const end = ep.next + 2 + len;
                if (pending.byteLength < end) break;
                const payload = pending.slice(ep.next + 2, end);
                onPacket(ep, payload);
                pending = pending.slice(end);
            }
        });
        this.ws.addEventListener('close', () => { this.close(); onClose(); });
        this.ws.addEventListener('error', () => { this.close(); onClose(); });
    }

    close() {
        if (this.closed) return;
        this.closed = true;
        safeCloseWebSocket(this.ws);
    }
}

function parseEarlyDataLimit(url) {
    const raw = url?.searchParams?.get('ed');
    const n = Number(raw);
    return Number.isInteger(n) && n > 0 && n <= 8192 ? n : 0;
}

function decodeEarlyData(header, maxBytes = 8192) {
    if (!header) return null;
    try {
        let token = header.trim().split(',')[0].trim().replace(/-/g, '+').replace(/_/g, '/');
        const rem = token.length % 4;
        if (rem) token += '='.repeat(4 - rem);
        const decoded = atob(token);
        return Uint8Array.from(decoded, (c) => c.charCodeAt(0));
    } catch { return null; }
}

async function toUint8Array(value) {
    if (value instanceof Uint8Array) return value;
    if (value instanceof ArrayBuffer) return new Uint8Array(value);
    if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    if (typeof Blob !== 'undefined' && value instanceof Blob) return new Uint8Array(await value.arrayBuffer());
    throw new TypeError('unsupported payload');
}
function uint16be(value) { return new Uint8Array([value >>> 8, value & 0xff]); }
function safeCloseWebSocket(ws) {
    try { if (ws.readyState === WS_OPEN || ws.readyState === WS_CLOSING) ws.close(); } catch { }
}

function generateCleanUI(serverHost, currentConfig) {
    const uuidsJson = JSON.stringify(currentConfig.UUID_LIST);
    return `<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Config Generator</title>
    <style>
        :root {
            --bg: #f8fafc;
            --card-bg: #ffffff;
            --text: #0f172a;
            --muted: #64748b;
            --border: #e2e8f0;
            --primary: #2563eb;
            --header: #334155;
            --danger: #ef4444;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background: var(--bg); color: var(--text); padding: 16px; display: flex; justify-content: center; }
        .container { width: 100%; max-width: 480px; }
        .app-bar { display: flex; align-items: center; justify-content: space-between; padding: 8px 4px 16px; }
        .tab-btn { background: none; border: none; font-size: 0.9rem; font-weight: 600; color: var(--muted); cursor: pointer; padding: 6px 14px; border-radius: 6px; }
        .tab-btn.active { color: var(--primary); background: #e0e7ff; }
        
        .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; padding: 20px; box-shadow: 0 4px 12px rgba(0,0,0,0.03); margin-bottom: 16px; }
        .badge { font-size: 0.8rem; font-weight: 600; color: #64748b; border-bottom: 1px solid var(--border); padding-bottom: 10px; margin-bottom: 14px; }
        
        .dt-item { margin-bottom: 12px; }
        .dt-label { font-size: 0.72rem; color: #94a3b8; text-transform: lowercase; font-weight: 600; display: block; margin-bottom: 2px; }
        .dt-value { font-size: 0.92rem; color: #334155; font-family: monospace; word-break: break-all; }
        
        .form-group { margin-bottom: 14px; }
        label { display: block; font-size: 0.78rem; font-weight: 600; color: #475569; margin-bottom: 5px; }
        input, select { width: 100%; padding: 10px 12px; border-radius: 8px; border: 1px solid var(--border); background: #f8fafc; font-size: 0.9rem; color: #1e293b; outline: none; }
        input:focus, select:focus { border-color: var(--primary); background: #fff; }
        
        .btn-action { width: 100%; padding: 11px; background: var(--primary); color: #fff; border: none; border-radius: 8px; font-weight: 700; cursor: pointer; margin-top: 4px; }
        .btn-action:hover { opacity: 0.9; }
        .btn-danger { background: var(--danger); width: auto; padding: 6px 10px; font-size: 0.75rem; border-radius: 6px; }
        
        .uuid-list { list-style: none; margin-top: 10px; }
        .uuid-item { display: flex; align-items: center; justify-content: space-between; padding: 8px 10px; border: 1px solid var(--border); border-radius: 6px; margin-bottom: 6px; font-family: monospace; font-size: 0.75rem; }
        
        .raw-link { width: 100%; height: 85px; background: #f1f5f9; border: 1px solid var(--border); border-radius: 6px; font-family: monospace; font-size: 0.78rem; color: #334155; padding: 8px; margin-top: 10px; resize: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="app-bar">
            <span style="font-weight:700; color: #334155;">Universal Config</span>
            <div>
                <button class="tab-btn active" onclick="showTab('gen')">Config</button>
                <button class="tab-btn" onclick="showTab('kv')">Settings (KV)</button>
            </div>
        </div>

        <div id="tab-gen">
            <div class="card">
                <div class="badge" id="dtBadge">Auto / Any • Websocket SSL/TLS</div>
                <div class="dt-item">
                    <span class="dt-label">target server (address)</span>
                    <span class="dt-value" id="dtTarget">api.quipper.com:443</span>
                </div>
                <div class="dt-item">
                    <span class="dt-label">uuid / password</span>
                    <span class="dt-value" id="dtUuid">${currentConfig.ACTIVE_UUID}</span>
                </div>
                <div class="dt-item">
                    <span class="dt-label">default proxy ip aktif</span>
                    <span class="dt-value" id="dtProxyActive">${currentConfig.DEFAULT_PROXY_IP || '(Direct Socket - Kosong)'}</span>
                </div>
                <div class="dt-item">
                    <span class="dt-label">path</span>
                    <span class="dt-value" id="dtPath">/</span>
                </div>
                <div class="dt-item">
                    <span class="dt-label">server name indication (sni)</span>
                    <span class="dt-value" id="dtSni">${serverHost}</span>
                </div>
                <div class="dt-item">
                    <span class="dt-label">header host</span>
                    <span class="dt-value" id="dtHost">${serverHost}</span>
                </div>
            </div>

            <div class="card">
                <div class="form-group">
                    <label>Protokol (Format Import)</label>
                    <select id="proto" onchange="render()">
                        <option value="vless" selected>VLESS (WS)</option>
                        <option value="vmess">VMess (WS)</option>
                        <option value="trojan">Trojan (WS)</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Gunakan UUID / Auth</label>
                    <select id="selectUuid" onchange="render()"></select>
                </div>
                <div class="form-group">
                    <label>Target Server / Bug SNI (Host:Port)</label>
                    <input type="text" id="targetServer" value="api.quipper.com:443" oninput="render()">
                </div>
                <div class="form-group">
                    <label>Custom UDP Relay (Format '=' contoh: domain=443)</label>
                    <input type="text" id="udpTarget" placeholder="Contoh: wsudprelay.up.railway.app=443" oninput="render()">
                </div>
                <div class="form-group">
                    <label>Proxy Target (Format ':' contoh: 103.196.155.151:443)</label>
                    <input type="text" id="proxyTarget" placeholder="Contoh: 103.196.155.151:443" oninput="render()">
                </div>
                <textarea id="rawOutput" class="raw-link" readonly></textarea>
                <button class="btn-action" onclick="copyLink()">Salin URL Import</button>
            </div>
        </div>

        <div id="tab-kv" style="display: none;">
            <div class="card">
                <h3 style="font-size: 0.95rem; margin-bottom: 12px; color: #1e293b;">Default Proxy IP (Bypass & Anti-Loop)</h3>
                <div class="form-group">
                    <label>Proxy IP Aktif (Contoh: 103.196.155.151:443)</label>
                    <input type="text" id="proxyIpInput" value="${currentConfig.DEFAULT_PROXY_IP}" placeholder="IP:Port (Kosongkan jika Direct)">
                </div>
                <button class="btn-action" onclick="saveProxyIpKV()">Simpan Default Proxy IP</button>
            </div>

            <div class="card">
                <h3 style="font-size: 0.95rem; margin-bottom: 12px; color: #1e293b;">Kelola Multi UUID</h3>
                <div class="form-group">
                    <label>Tambah UUID / Kata Sandi Baru</label>
                    <input type="text" id="newUuidInput" placeholder="Masukkan UUID atau teks baru...">
                </div>
                <button class="btn-action" onclick="addUuidKV()">Tambah UUID ke KV</button>
                <ul class="uuid-list" id="uuidContainer"></ul>
            </div>

            <div class="card">
                <h3 style="font-size: 0.95rem; margin-bottom: 12px; color: #1e293b;">Pengaturan DNS DoH</h3>
                <div class="form-group">
                    <label>Pilihan Resolver DoH</label>
                    <select id="dohPreset" onchange="changeDohPreset()">
                        <option value="https://cloudflare-dns.com/dns-query">Cloudflare (Default)</option>
                        <option value="https://dns.google/dns-query">Google DNS</option>
                        <option value="https://dns.adguard.com/dns-query">AdGuard DNS</option>
                        <option value="https://dns.quad9.net/dns-query">Quad9</option>
                        <option value="https://dns.alidns.com/dns-query">AliDNS</option>
                        <option value="custom">-- Custom URL DoH --</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>URL DoH Aktif</label>
                    <input type="text" id="dohInput" value="${currentConfig.DNS_DOH_URL}">
                </div>
                <button class="btn-action" onclick="saveDnsKV()">Simpan Pengaturan DNS DoH</button>
            </div>

            <div class="card">
                <h3 style="font-size: 0.95rem; margin-bottom: 12px; color: #1e293b;">Pengaturan UDP Relay (Fallback Default)</h3>
                <div class="form-group">
                    <label>UDP Relay Host (Railway Domain)</label>
                    <input type="text" id="udpHost" value="${currentConfig.UDP_RELAY_HOST}">
                </div>
                <div class="form-group">
                    <label>UDP Relay Port</label>
                    <input type="number" id="udpPort" value="${currentConfig.UDP_RELAY_PORT}">
                </div>
                <button class="btn-action" onclick="saveUdpKV()">Simpan Pengaturan UDP Relay</button>
            </div>
        </div>
    </div>

    <script>
        const host = window.location.host;
        let uuidList = ${uuidsJson};
        let activeProxyIp = "${currentConfig.DEFAULT_PROXY_IP}";

        function showTab(tab) {
            document.getElementById('tab-gen').style.display = tab === 'gen' ? 'block' : 'none';
            document.getElementById('tab-kv').style.display = tab === 'kv' ? 'block' : 'none';
            document.querySelectorAll('.tab-btn').forEach((b, idx) => {
                b.classList.toggle('active', (tab === 'gen' && idx === 0) || (tab === 'kv' && idx === 1));
            });
        }

        function populateUuids() {
            const sel = document.getElementById('selectUuid');
            const cont = document.getElementById('uuidContainer');
            sel.innerHTML = '';
            cont.innerHTML = '';
            uuidList.forEach(u => {
                const opt = document.createElement('option');
                opt.value = u;
                opt.innerText = u;
                sel.appendChild(opt);

                const li = document.createElement('li');
                li.className = 'uuid-item';
                li.innerHTML = '<span>' + u + '</span><button class="btn-action btn-danger" onclick="deleteUuidKV(\\'' + u + '\\')">Hapus</button>';
                cont.appendChild(li);
            });
        }

        function changeDohPreset() {
            const val = document.getElementById('dohPreset').value;
            if (val !== 'custom') {
                document.getElementById('dohInput').value = val;
            }
        }

        function render() {
            const p = document.getElementById('proto').value;
            const target = document.getElementById('targetServer').value.trim() || host + ':443';
            let udp = document.getElementById('udpTarget').value.trim();
            const proxy = document.getElementById('proxyTarget').value.trim();
            const activeUuid = document.getElementById('selectUuid').value || uuidList[0];

            let pathSegments = [];
            if (udp) {
                udp = udp.replace(':', '=');
                pathSegments.push(udp);
            }
            if (proxy) {
                pathSegments.push(proxy);
            }

            const path = '/' + pathSegments.join('/');

            let labelProto = 'VLESS • Auto-Detect';
            if (p === 'vmess') labelProto = 'VMess • Auto-Detect';
            if (p === 'trojan') labelProto = 'Trojan • Auto-Detect';

            document.getElementById('dtBadge').innerText = labelProto;
            document.getElementById('dtTarget').innerText = target;
            document.getElementById('dtUuid').innerText = activeUuid;
            document.getElementById('dtPath').innerText = path;
            document.getElementById('dtSni').innerText = host;
            document.getElementById('dtHost').innerText = host;
            document.getElementById('dtProxyActive').innerText = activeProxyIp || '(Direct Socket - Kosong)';

            const [targetHost, targetPort] = target.split(':');
            const port = targetPort || '443';
            let link = '';
            const remarks = (udp ? '[UDP] ' : '') + (proxy ? 'CustomProxy' : (activeProxyIp ? 'ProxyIP' : 'Direct'));

            if (p === 'vmess') {
                link = 'vmess://' + btoa(unescape(encodeURIComponent(JSON.stringify({
                    v: "2", ps: "VMess-" + remarks, add: targetHost, port: port, id: activeUuid, aid: "0", scy: "auto", net: "ws", type: "none", host: host, path: path, tls: "tls", sni: host, alpn: "http/1.1", fp: "chrome"
                }))));
            } else if (p === 'vless') {
                link = 'vless://' + activeUuid + '@' + targetHost + ':' + port + '?encryption=none&security=tls&sni=' + host + '&alpn=http/1.1&fp=chrome&type=ws&host=' + host + '&path=' + encodeURIComponent(path) + '#' + 'VLESS-' + remarks;
            } else {
                link = 'trojan://' + activeUuid + '@' + targetHost + ':' + port + '?security=tls&sni=' + host + '&alpn=http/1.1&fp=chrome&type=ws&host=' + host + '&path=' + encodeURIComponent(path) + '#' + 'Trojan-' + remarks;
            }
            document.getElementById('rawOutput').value = link;
        }

        function copyLink() {
            const text = document.getElementById('rawOutput').value;
            if (!text) return;
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(text).then(() => {
                    alert('Config disalin!');
                }).catch(() => {
                    fallbackCopy(text);
                });
            } else {
                fallbackCopy(text);
            }
        }

        function fallbackCopy(str) {
            const ta = document.createElement('textarea');
            ta.value = str;
            ta.style.position = 'fixed';
            ta.style.left = '-999999px';
            ta.style.top = '-999999px';
            document.body.appendChild(ta);
            ta.focus();
            ta.select();
            try {
                const success = document.execCommand('copy');
                if (success) alert('Config disalin!');
                else prompt('Salin manual config:', str);
            } catch {
                prompt('Salin manual config:', str);
            }
            document.body.removeChild(ta);
        }

        async function postSettings(payload) {
            try {
                const res = await fetch('/api/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (data.success) {
                    alert('Berhasil disimpan ke KV!');
                    if (data.config) {
                        if (data.config.UUID_LIST) uuidList = data.config.UUID_LIST;
                        if (data.config.DEFAULT_PROXY_IP !== undefined) activeProxyIp = data.config.DEFAULT_PROXY_IP;
                        populateUuids();
                        render();
                    }
                } else {
                    alert('Gagal: ' + (data.error || 'Terjadi kesalahan'));
                }
            } catch (err) {
                alert('Gagal simpan ke KV: ' + err.message);
            }
        }

        function saveProxyIpKV() {
            postSettings({
                action: 'save_proxy_ip',
                DEFAULT_PROXY_IP: document.getElementById('proxyIpInput').value.trim()
            });
        }

        function saveDnsKV() {
            postSettings({
                action: 'save_dns',
                DNS_DOH_URL: document.getElementById('dohInput').value.trim()
            });
        }

        function saveUdpKV() {
            postSettings({
                action: 'save_udp',
                UDP_RELAY_HOST: document.getElementById('udpHost').value.trim(),
                UDP_RELAY_PORT: Number(document.getElementById('udpPort').value.trim())
            });
        }

        function addUuidKV() {
            const val = document.getElementById('newUuidInput').value.trim();
            if (!val) return alert('UUID tidak boleh kosong!');
            postSettings({ action: 'add_uuid', uuid: val });
            document.getElementById('newUuidInput').value = '';
        }

        function deleteUuidKV(u) {
            if (!confirm('Yakin ingin menghapus UUID ini?')) return;
            postSettings({ action: 'delete_uuid', uuid: u });
        }

        populateUuids();
        render();
    </script>
</body>
</html>`;
}
