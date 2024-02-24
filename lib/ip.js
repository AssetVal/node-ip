"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
/* eslint-disable indent */
/* eslint-disable @typescript-eslint/no-redundant-type-constituents */
const node_buffer_1 = require("node:buffer");
const node_os_1 = __importDefault(require("node:os"));
;
/**
 * IP utility class providing static methods for IP address manipulation.
 */
class IP {
    static ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    /** Regular expression for matching IPv6 addresses that are mapped from IPv4 addresses */
    static ipv4MappedV6Regex = /^::ffff:((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$/i;
    /** Regular expression for matching IPv6 addresses */
    static ipv6Regex = /^([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])$/;
    /** Regular expression for matching Unique Local Addresses (ULAs) */
    static ulaV6Regex = /^fd[0-9a-f]{2}:/i;
    /** Regular expression for matching link-local IPv6 addresses */
    static linkLocalV6Regex = /^fe80:/i;
    /** Regular expression for matching any unspecified IPv6 address */
    static unspecifiedV6Regex = /^::$/i;
    /** Regular expression for matching private IPv4 addresses */
    static privateV4Regex = /^(::f{4}:)?((10\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(172\.(1[6-9]|2\d|3[0-1])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(192\.168\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(169\.254\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])))$/i;
    /** Regular expression for matching private IPv6 addresses that are mapped from IPv4 addresses */
    static privateV4MappedV6Regex = /^::ffff:((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$/i;
    /** Regular expression for matching loopback IPv6 addresses */
    static loopbackV6Regex = /^::1$/i;
    /** Regular expression for matching IPv4 loopback addresses */
    static loopbackV4Regex = /^(::f{4}:)?127\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/i;
    /** Regular Expression for matching loopback IPv4 addresses starting with 0177 */
    static loopbackV4_0177 = /^0177\./;
    /** Regular Expression for matching hexadecimal loopback IPv4 addresses */
    static loopbackV4_hex = /^0x7f\./;
    /**
     * Converts an IPv4 address to a Buffer.
     * @param {IPAddress} ip - The IPv4 address to convert.
     * @param {Buffer} buff - An optional Buffer to write the result to.
     * @param {number} offset - The offset in the Buffer to start writing at.
     * @returns {Buffer} The Buffer containing the IPv4 address.
     */
    static toBufferV4(ip, buff, offset = 0) {
        const result = buff ?? node_buffer_1.Buffer.alloc(offset + 4);
        ip.split(/\./g).forEach((byte) => {
            result[offset++] = parseInt(byte, 10) & 0xff;
        });
        return result;
    }
    /**
     * Converts an IPv6 address to a Buffer.
     * @param {IPAddress} ip - The IPv6 address to convert.
     * @param {Buffer} buff - An optional Buffer to write the result to.
     * @param {number} offset - The offset in the Buffer to start writing at.
     * @returns {Buffer} The Buffer containing the IPv6 address.
     */
    static toBufferV6(ip, buff, offset = 0) {
        const sections = ip.split(':', 8);
        let i;
        for (i = 0; i < sections.length; i++) {
            const isv4 = this.isV4Format(sections[i]) || this.privateV4MappedV6Regex.test(sections[i]);
            let v4Buffer;
            if (isv4) {
                v4Buffer = this.toBuffer(sections[i]);
                sections[i] = v4Buffer.slice(0, 2).toString('hex');
            }
            if (v4Buffer && ++i < 8) {
                sections.splice(i, 0, v4Buffer.slice(2, 4).toString('hex'));
            }
        }
        if (sections[0] === '') {
            while (sections.length < 8)
                sections.unshift('0');
        }
        else if (sections[sections.length - 1] === '') {
            while (sections.length < 8)
                sections.push('0');
        }
        else if (sections.length < 8) {
            for (i = 0; i < sections.length && sections[i] !== ''; i++)
                ;
            const argv = [i, 1];
            for (i = 9 - sections.length; i > 0; i--) {
                argv.push('0');
            }
            sections.splice(...argv);
        }
        const result = buff ?? node_buffer_1.Buffer.alloc(offset + 16);
        for (i = 0; i < sections.length; i++) {
            const word = parseInt(sections[i], 16);
            result[offset++] = (word >> 8) & 0xff;
            result[offset++] = word & 0xff;
        }
        return result;
    }
    static toBufferIPV6MappedIPV4(ip, buff, offset = 0) {
        // Extract the IPv4 part from the IPv4-mapped IPv6 address
        const ipv4Part = ip.replace(/^::ffff:/, '');
        const v4Buffer = this.toBuffer(ipv4Part);
        // Create a buffer for the IPv6 address with the IPv4 part expanded
        const result = buff ?? node_buffer_1.Buffer.alloc(offset + 16);
        result.fill(0, offset, offset + 10); // Fill the first  10 bytes with zeros
        result.fill(0xff, offset + 10, offset + 12); // Fill the next  2 bytes with  0xff
        v4Buffer.copy(result, offset + 12); // Copy the IPv4 part into the last  4 bytes
        return result;
    }
    /**
     * Converts an IP address to a Buffer.
     * @param {IPAddress} ip - The IP address to convert.
     * @param {Buffer} buff - An optional Buffer to write the result to.
     * @param {number} offset - The offset in the Buffer to start writing at.
     * @returns {Buffer} The Buffer containing the IP address.
     */
    static toBuffer(ip, buff, offset = 0) {
        offset = ~~offset;
        let result;
        if (this.isV4Format(ip)) {
            if (this.ipv4MappedV6Regex.test(ip)) {
                result = this.toBufferIPV6MappedIPV4(ip, buff, offset);
            }
            else {
                result = this.toBufferV4(ip, buff, offset);
            }
        }
        else if (this.isV6Format(ip)) {
            result = this.toBufferV6(ip, buff, offset);
        }
        if (!result) {
            throw Error(`Invalid ip address: ${ip}`);
        }
        return result;
    }
    /**
     * Converts a Buffer to an IP address string.
     * @param buff - The Buffer containing the IP address.
     * @param offset - The offset in the Buffer to start reading from.
     * @param length - The length of the IP address in the Buffer.
     * @returns The IP address string.
     */
    static toString(buff, offset = 0, length = buff.length - offset) {
        offset = ~~offset;
        length = length || (buff.length - offset);
        let result = '';
        if (length === 4) {
            // IPv4
            for (let i = 0; i < length; i++) {
                result += ((i > 0) ? '.' : '') + buff[offset + i];
            }
        }
        else if (length === 16) {
            // IPv6
            for (let i = 0; i < length; i += 2) {
                const word = buff.readUInt16BE(offset + i);
                result += ((i > 0) ? ':' : '') + word.toString(16);
            }
            result = result.replace(/(^|:)0(:0)*:0(:|$)/, '$1::$3');
            result = result.replace(/:{3,4}/, '::');
        }
        return result;
    }
    /**
     * Checks if an IP address is in IPv4 format.
     * @param ip - The IP address to check.
     * @returns True if the IP address is in IPv4 format, false otherwise.
     */
    static isV4Format(ip) {
        return this.ipv4Regex.test(ip) ||
            this.privateV4Regex.test(ip) ||
            this.loopbackV4Regex.test(ip);
    }
    /**
     * Checks if an IP address is in IPv6 format.
     * @param ip - The IP address to check.
     * @returns True if the IP address is in IPv6 format, false otherwise.
     */
    static isV6Format(ip) {
        return this.ipv6Regex.test(ip) ||
            this.ipv4MappedV6Regex.test(ip) ||
            this.ulaV6Regex.test(ip) ||
            this.linkLocalV6Regex.test(ip) ||
            this.loopbackV6Regex.test(ip) ||
            this.unspecifiedV6Regex.test(ip);
    }
    /**
     * Normalizes the family parameter to either 'ipv4' or 'ipv6'.
     * @param family - The family parameter to normalize.
     * @returns The normalized family parameter.
     */
    static normalizeFamily(family) {
        return (typeof family === 'number')
            ? `ipv${family}`
            : family.toLowerCase();
    }
    /**
     * Generates an IP address from a prefix length.
     * @param prefixlen - The prefix length.
     * @param family - The IP family (optional, defaults to 'ipv4').
     * @returns The generated IP address.
     */
    static fromPrefixLen(prefixlen, family = 'ipv4') {
        if (prefixlen > 32)
            family = 'ipv6';
        if (family !== 'ipv4' && family !== 'ipv6')
            family = this.normalizeFamily(family);
        if (prefixlen < 0 || (family === 'ipv4' && prefixlen > 32) || (family === 'ipv6' && prefixlen > 128)) {
            throw new Error(`Invalid prefix length: ${prefixlen}`);
        }
        const len = (family === 'ipv4') ? 4 : 16;
        const buff = node_buffer_1.Buffer.alloc(len);
        for (let i = 0; i < len; i++) {
            const bits = Math.min(prefixlen, 8);
            buff[i] = (prefixlen > 0) ? (~(0xff >> bits) & 0xff) : 0;
            prefixlen -= bits;
        }
        return this.toString(buff);
    }
    /**
     * Applies a mask to an IP address.
     * @param addr - The IP address to mask.
     * @param mask - The mask to apply.
     * @returns The masked IP address.
     */
    static mask(addr, mask) {
        const addrBuffer = this.toBuffer(addr);
        const maskBuffer = this.toBuffer(mask);
        const result = node_buffer_1.Buffer.alloc(Math.max(addrBuffer.length, maskBuffer.length));
        let i = 0;
        if (addrBuffer.length === maskBuffer.length) {
            for (i = 0; i < addrBuffer.length; i++) {
                result[i] = addrBuffer[i] & maskBuffer[i];
            }
        }
        else if (maskBuffer.length === 4) {
            for (i = 0; i < maskBuffer.length; i++) {
                result[i] = addrBuffer[addrBuffer.length - 4 + i] & maskBuffer[i];
            }
        }
        else {
            for (let z = 0; z < result.length - 6; z++) {
                result[z] = 0;
            }
            result[10] = 0xff;
            result[11] = 0xff;
            for (i = 0; i < addrBuffer.length; i++) {
                result[i + 12] = addrBuffer[i] & maskBuffer[i + 12];
            }
            i += 12;
        }
        for (; i < result.length; i++)
            result[i] = 0;
        return this.toString(result);
    }
    /**
   * Applies a mask to an IP address based on a CIDR string.
   * @param cidrString - The CIDR string to apply the mask from.
   * @returns The masked IP address.
   */
    static cidr(cidrString) {
        const cidrParts = cidrString.split('/');
        if (cidrParts.length !== 2) {
            throw new Error(`Invalid CIDR subnet: ${cidrString}`);
        }
        const addr = cidrParts[0];
        const mask = this.fromPrefixLen(parseInt(cidrParts[1], 10));
        return this.mask(addr, mask);
    }
    /**
     * Applies a mask to an IP address based on a CIDR subnet string.
     * @param cidrString - The CIDR subnet string to apply the mask from.
     * @returns The masked IP address.
     */
    static cidrSubnet(cidrString) {
        const cidrParts = cidrString.split('/');
        if (cidrParts.length !== 2) {
            throw new Error(`Invalid CIDR subnet: ${cidrString}`);
        }
        const addr = cidrParts[0];
        const mask = this.fromPrefixLen(parseInt(cidrParts[1], 10));
        return this.subnet(addr, mask);
    }
    /**
     * Performs a bitwise NOT operation on an IP address.
     * @param addr - The IP address to invert.
     * @returns The inverted IP address.
     */
    static not(addr) {
        const buff = this.toBuffer(addr);
        for (let i = 0; i < buff.length; i++) {
            buff[i] ^= 0xff;
        }
        return this.toString(buff);
    }
    /**
     * Performs a bitwise OR operation on two IP addresses.
     * @param a - The first IP address.
     * @param b - The second IP address.
     * @returns The result of the bitwise OR operation.
     */
    static or(a, b) {
        const aBuffer = this.toBuffer(a);
        const bBuffer = this.toBuffer(b);
        // Same protocol
        if (aBuffer.length === bBuffer.length) {
            for (let i = 0; i < aBuffer.length; i++) {
                aBuffer[i] |= bBuffer[i];
            }
            return this.toString(aBuffer);
        }
        // Mixed protocols
        const buff = (aBuffer.length > bBuffer.length) ? aBuffer : bBuffer;
        const other = (aBuffer.length > bBuffer.length) ? bBuffer : aBuffer;
        const offset = buff.length - other.length;
        for (let i = offset; i < buff.length; i++) {
            buff[i] |= other[i - offset];
        }
        return this.toString(buff);
    }
    /**
     * Checks if two IP addresses are equal.
     * @param a - The first IP address.
     * @param b - The second IP address.
     * @returns True if the IP addresses are equal, false otherwise.
     */
    static isEqual(a, b) {
        let aBuffer = this.toBuffer(a);
        let bBuffer = this.toBuffer(b);
        // Same protocol
        if (aBuffer.length === bBuffer.length) {
            for (let i = 0; i < aBuffer.length; i++) {
                if (aBuffer[i] !== bBuffer[i])
                    return false;
            }
            return true;
        }
        // Swap
        if (bBuffer.length === 4) {
            const t = bBuffer;
            bBuffer = aBuffer;
            aBuffer = t;
        }
        // a - IPv4, b - IPv6
        for (let i = 0; i < 10; i++) {
            if (bBuffer[i] !== 0)
                return false;
        }
        const word = bBuffer.readUInt16BE(10);
        if (word !== 0 && word !== 0xffff)
            return false;
        for (let i = 0; i < 4; i++) {
            if (aBuffer[i] !== bBuffer[i + 12])
                return false;
        }
        return true;
    }
    /**
   * Checks if an IP address is a private IPv4 address.
   * @param ip - The IP address to check.
   * @returns True if the IP address is private, false otherwise.
   */
    static isPrivateV4(ip) {
        return this.privateV4Regex.test(ip);
    }
    /**
     * Checks if an IP address is a private IPv6 address.
     * @param ip - The IP address to check.
     * @returns True if the IP address is private, false otherwise.
     */
    static isPrivateV6(ip) {
        return this.ulaV6Regex.test(ip) || this.linkLocalV6Regex.test(ip) || this.loopbackV6Regex.test(ip) || this.unspecifiedV6Regex.test(ip);
    }
    /**
     * Checks if an IP address is a private address.
     * @param addr - The IP address to check.
     * @returns True if the IP address is private, false otherwise.
     */
    static isPrivate(addr) {
        return this.privateV4Regex.test(addr) ||
            this.loopbackV4Regex.test(addr) ||
            this.ulaV6Regex.test(addr) ||
            this.linkLocalV6Regex.test(addr) ||
            this.loopbackV6Regex.test(addr) ||
            this.unspecifiedV6Regex.test(addr) ||
            this.privateV4MappedV6Regex.test(addr) ||
            this.loopbackV4_hex.test(addr);
    }
    /**
   * Calculates the subnet details for a given IP address and mask.
   * @param addr - The IP address.
   * @param mask - The subnet mask.
   * @returns An object containing the subnet details.
   */
    static subnet(addr, mask) {
        const networkAddress = this.toLong(this.mask(addr, mask));
        const maskBuffer = this.toBuffer(mask);
        let maskLength = 0;
        let done = false;
        for (const octet of maskBuffer) {
            if (done) {
                break;
            }
            if (octet === 0xff) {
                maskLength += 8;
            }
            else {
                let bit = 0x80;
                while (bit & octet) {
                    maskLength++;
                    bit >>= 1;
                }
                done = true;
            }
        }
        const numberOfAddresses = 2 ** (32 - maskLength);
        return {
            networkAddress: this.fromLong(networkAddress),
            firstAddress: (numberOfAddresses <= 2) ?
                this.fromLong(networkAddress) :
                this.fromLong(networkAddress + 1),
            lastAddress: (numberOfAddresses <= 2) ?
                this.fromLong(networkAddress + numberOfAddresses - 1) :
                this.fromLong(networkAddress + numberOfAddresses - 2),
            broadcastAddress: this.fromLong(networkAddress + numberOfAddresses - 1),
            subnetMask: mask,
            subnetMaskLength: maskLength,
            numHosts: (numberOfAddresses <= 2) ? numberOfAddresses : (numberOfAddresses - 2),
            length: numberOfAddresses,
            contains: (other) => networkAddress === this.toLong(this.mask(other, mask))
        };
    }
    /**
     * Converts an IP address to a long integer representation.
     *
     * @param ip The IP address to convert.
     * @returns The long integer representation of the IP address.
     */
    static toLong(ip) {
        let ipl = 0;
        // Split the IP address into its four octets.
        ip.split('.').forEach((octet) => {
            // Bit-shift the current integer representation 8 bits to the left to make room for the next octet.
            ipl <<= 8;
            // Add the integer value of the current octet to the integer representation.
            ipl += parseInt(octet);
        });
        // Return the integer representation as an unsigned 32-bit integer.
        return (ipl >>> 0);
    }
    /**
     * Converts a long integer to an IP address.
     * @param long - The long integer to convert.
     * @returns The IP address string.
     */
    static fromLong(long) {
        const ipBuffer = node_buffer_1.Buffer.alloc(4);
        for (let i = 0; i < 4; i++) {
            ipBuffer[i] = (long >> (8 * (3 - i))) & 0xff;
        }
        return this.toString(ipBuffer);
    }
    /**
     * Checks if an IP address is a public address.
     * @param ip - The IP address to check.
     * @returns True if the IP address is public, false otherwise.
     */
    static isPublic(ip) {
        return !this.isPrivate(ip);
    }
    /**
     * Returns the loopback address for the given IP family.
     * @param family - The IP family (optional, defaults to 'ipv4').
     * @returns The loopback address.
     */
    static loopback(family = 'ipv4') {
        //
        // Default to `ipv4`
        //
        family = this.normalizeFamily(family);
        if (family !== 'ipv4' && family !== 'ipv6') {
            throw new Error('family must be ipv4 or ipv6');
        }
        return family === 'ipv4' ? '127.0.0.1' : 'fe80::1';
    }
    /**
     * Checks if an IP address is a loopback address.
     * @param ip - The IP address to check.
     * @returns True if the IP address is a loopback address, false otherwise.
     */
    static isLoopback(ip) {
        // If addr is an IPv4 address in long integer form (no dots and no colons), convert it
        if (!/\./.test(ip) && !/:/.test(ip)) {
            ip = IP.fromLong(Number(ip));
        }
        return this.loopbackV4Regex.test(ip) ||
            this.loopbackV4_0177.test(ip) ||
            this.loopbackV4_hex.test(ip) ||
            this.loopbackV6Regex.test(ip) ||
            this.unspecifiedV6Regex.test(ip) ||
            this.linkLocalV6Regex.test(ip);
    }
    /**
     * Returns the address for the network interface on the current system with the specified `name`.
     * @param name - The name or security of the network interface.
     * @param family - The IP family of the address (defaults to 'ipv4').
     * @returns The address for the network interface.
     */
    static address(name, family = 'ipv4') {
        family = this.normalizeFamily(family);
        const interfaces = node_os_1.default.networkInterfaces();
        if (name && name !== 'private' && name !== 'public') {
            const res = interfaces[name]?.filter((details) => {
                const itemFamily = this.normalizeFamily(details.family);
                return itemFamily === family && !this.isLoopback(details.address);
            });
            return (res?.length) ? res[0].address : undefined;
        }
        const all = Object.values(interfaces)
            .flatMap((details) => details?.filter((detail) => {
            const itemFamily = this.normalizeFamily(detail.family);
            if (itemFamily !== family || this.isLoopback(detail.address))
                return false;
            if (!name)
                return true;
            return (name === 'public') ? this.isPrivate(detail.address) : this.isPublic(detail.address);
        }))
            .map((detail) => detail?.address);
        return all.length
            ? all[0]
            : this.loopback(family);
    }
    static normalizeToLong(addr) {
        const parts = addr.split('.').map(part => {
            // Handle hexadecimal format
            if (part.startsWith('0x') || part.startsWith('0X')) {
                return parseInt(part.slice(2), 16);
            }
            // Handle octal format (strictly digits  0-7 after a leading zero)
            if (part.startsWith('0') && part !== '0' && /^[0-7]+$/.test(part)) {
                return parseInt(part, 8);
            }
            // Handle decimal format, reject invalid leading zeros
            if (/^[1-9]\d*$/.test(part) || part === '0') {
                return parseInt(part, 10);
            }
            // Return NaN for invalid formats to indicate parsing failure
            return NaN;
        });
        if (parts.some(Number.isNaN))
            return -1; // Indicate error with -1
        let val = 0;
        const n = parts.length;
        switch (n) {
            case 1:
                [val] = parts;
                break;
            case 2: {
                if (parts[0] > 0xff || parts[1] > 0xffffff)
                    return -1;
                val = (parts[0] << 24) | (parts[1] & 0xffffff);
                break;
            }
            case 3: {
                if (parts[0] > 0xff || parts[1] > 0xff || parts[2] > 0xffff)
                    return -1;
                val = (parts[0] << 24) | (parts[1] << 16) | (parts[2] & 0xffff);
                break;
            }
            case 4: {
                if (parts.some(part => part > 0xff))
                    return -1;
                val = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
                break;
            }
            default: return -1; // Error case
        }
        return val >>> 0;
    }
}
exports.default = IP;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaXAuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyJpcC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7OztBQUFBLDJCQUEyQjtBQUMzQixzRUFBc0U7QUFDdEUsNkNBQXFDO0FBQ3JDLHNEQUF5QjtBQTRCeEIsQ0FBQztBQUVGOztHQUVHO0FBQ0gsTUFBcUIsRUFBRTtJQUNiLE1BQU0sQ0FBVSxTQUFTLEdBQUcsa0tBQWtLLENBQUM7SUFDdk0seUZBQXlGO0lBQ2pGLE1BQU0sQ0FBVSxpQkFBaUIsR0FBRyw0S0FBNEssQ0FBQztJQUV6TixxREFBcUQ7SUFDN0MsTUFBTSxDQUFVLFNBQVMsR0FBRyxxcEJBQXFwQixDQUFDO0lBQzFyQixvRUFBb0U7SUFDNUQsTUFBTSxDQUFVLFVBQVUsR0FBRyxrQkFBa0IsQ0FBQztJQUV4RCxnRUFBZ0U7SUFDeEQsTUFBTSxDQUFVLGdCQUFnQixHQUFHLFNBQVMsQ0FBQztJQUNyRCxtRUFBbUU7SUFDM0QsTUFBTSxDQUFVLGtCQUFrQixHQUFHLE9BQU8sQ0FBQztJQUVyRCw2REFBNkQ7SUFDckQsTUFBTSxDQUFVLGNBQWMsR0FBRyx3Z0JBQXdnQixDQUFDO0lBQ2xqQixpR0FBaUc7SUFDekYsTUFBTSxDQUFVLHNCQUFzQixHQUFHLDRLQUE0SyxDQUFDO0lBRTlOLDhEQUE4RDtJQUN0RCxNQUFNLENBQVUsZUFBZSxHQUFHLFFBQVEsQ0FBQztJQUNuRCw4REFBOEQ7SUFDdEQsTUFBTSxDQUFVLGVBQWUsR0FBRyw0REFBNEQsQ0FBQztJQUN2RyxpRkFBaUY7SUFDekUsTUFBTSxDQUFVLGVBQWUsR0FBRyxTQUFTLENBQUM7SUFDcEQsMEVBQTBFO0lBQ2xFLE1BQU0sQ0FBVSxjQUFjLEdBQUcsU0FBUyxDQUFDO0lBRW5EOzs7Ozs7T0FNRztJQUNLLE1BQU0sQ0FBQyxVQUFVLENBQUMsRUFBYSxFQUFFLElBQWEsRUFBRSxNQUFNLEdBQUcsQ0FBQztRQUNoRSxNQUFNLE1BQU0sR0FBRyxJQUFJLElBQUksb0JBQU0sQ0FB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