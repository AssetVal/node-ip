/* eslint-disable indent */
/* eslint-disable @typescript-eslint/no-redundant-type-constituents */
import { Buffer } from 'node:buffer';
import os from 'node:os';

type IPAddress = `${number}.${number}.${number}.${number}`
  | `${string}:${string}:${string}:${string}:${string}:${string}:${string}:${string}`
  | `${string | number}:${string | number}:${string | number}:${string | number}:${string | number}:${string | number}`
  | `${string | number}:${string | number}:${string | number}:${string | number}`
  | `${string | number}:${string | number}:${string | number}`
  | `::${number}.${number}.${number}.${number}`
  | `::${number}.${number}.${number}`
  | `::${number}.${number}`
  | `::${number}` | `::${string}` | '::'
  | `0x${string}`
  | `${number}`
  | `0${number}.${number}.${number}`

type IPFamilyNumbers = 4 | 6;
type IPFamilyStrings = 'ipv4' | 'ipv6' | 'IPv4' | 'IPv6' | 'IPV4' | 'IPV6';
type IPFamily = IPFamilyNumbers | IPFamilyStrings;
interface SubnetRecord {
  networkAddress: string;
  firstAddress: string;
  lastAddress: string;
  broadcastAddress: string;
  subnetMask: string;
  subnetMaskLength: number;
  numHosts: number;
  length: number;
  contains: (other: IPAddress) => boolean;
};

/**
 * IP utility class providing static methods for IP address manipulation.
 */
export default class IP {
  private static readonly ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  /** Regular expression for matching IPv6 addresses that are mapped from IPv4 addresses */
  private static readonly ipv4MappedV6Regex = /^::ffff:((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$/i;

  /** Regular expression for matching IPv6 addresses */
  private static readonly ipv6Regex = /^([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])$/;
  /** Regular expression for matching Unique Local Addresses (ULAs) */
  private static readonly ulaV6Regex = /^fd[0-9a-f]{2}:/i;

  /** Regular expression for matching link-local IPv6 addresses */
  private static readonly linkLocalV6Regex = /^fe80:/i;
  /** Regular expression for matching any unspecified IPv6 address */
  private static readonly unspecifiedV6Regex = /^::$/i;

  /** Regular expression for matching private IPv4 addresses */
  private static readonly privateV4Regex = /^(::f{4}:)?((10\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(172\.(1[6-9]|2\d|3[0-1])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(192\.168\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(169\.254\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])))$/i;
  /** Regular expression for matching private IPv6 addresses that are mapped from IPv4 addresses */
  private static readonly privateV4MappedV6Regex = /^::ffff:((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$/i;

  /** Regular expression for matching loopback IPv6 addresses */
  private static readonly loopbackV6Regex = /^::1$/i;
  /** Regular expression for matching IPv4 loopback addresses */
  private static readonly loopbackV4Regex = /^(::f{4}:)?127\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/i;
  /** Regular Expression for matching loopback IPv4 addresses starting with 0177 */
  private static readonly loopbackV4_0177 = /^0177\./;
  /** Regular Expression for matching hexadecimal loopback IPv4 addresses */
  private static readonly loopbackV4_hex = /^0x7f\./;

  /**
   * Converts an IPv4 address to a Buffer.
   * @param {IPAddress} ip - The IPv4 address to convert.
   * @param {Buffer} buff - An optional Buffer to write the result to.
   * @param {number} offset - The offset in the Buffer to start writing at.
   * @returns {Buffer} The Buffer containing the IPv4 address.
   */
  private static toBufferV4(ip: IPAddress, buff?: Buffer, offset = 0): Buffer {
    const result = buff ?? Buffer.alloc(offset + 4);
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
  private static toBufferV6(ip: IPAddress, buff?: Buffer, offset = 0): Buffer {
    const sections = ip.split(':', 8);

    let i;
    for (i = 0; i < sections.length; i++) {
      const isv4 = this.isV4Format(sections[i]) || this.privateV4MappedV6Regex.test(sections[i]);

      let v4Buffer;

      if (isv4) {
        v4Buffer = this.toBuffer(sections[i] as IPAddress);
        sections[i] = v4Buffer.slice(0, 2).toString('hex');
      }

      if (v4Buffer && ++i < 8) {
        sections.splice(i, 0, v4Buffer.slice(2, 4).toString('hex'));
      }
    }

    if (sections[0] === '') {
      while (sections.length < 8) sections.unshift('0');
    } else if (sections[sections.length - 1] === '') {
      while (sections.length < 8) sections.push('0');
    } else if (sections.length < 8) {
      for (i = 0; i < sections.length && sections[i] !== ''; i++);
      const argv: (string | number)[] = [i, 1];
      for (i = 9 - sections.length; i > 0; i--) {
        argv.push('0');
      }
      sections.splice(...argv as [number, number]);
    }

    const result = buff ?? Buffer.alloc(offset + 16);
    for (i = 0; i < sections.length; i++) {
      const word = parseInt(sections[i], 16);
      result[offset++] = (word >> 8) & 0xff;
      result[offset++] = word & 0xff;
    }

    return result;
  }

  private static toBufferIPV6MappedIPV4(ip: IPAddress, buff?: Buffer, offset = 0): Buffer {
    // Extract the IPv4 part from the IPv4-mapped IPv6 address
    const ipv4Part = ip.replace(/^::ffff:/, '');
    const v4Buffer = this.toBuffer(ipv4Part);

    // Create a buffer for the IPv6 address with the IPv4 part expanded
    const result = buff ?? Buffer.alloc(offset + 16);
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
  static toBuffer(ip: IPAddress | string, buff?: Buffer, offset = 0): Buffer {
    offset = ~~offset;
    let result: Buffer | undefined;

    if (this.isV4Format(ip)) {
      if (this.ipv4MappedV6Regex.test(ip)) {
        result = this.toBufferIPV6MappedIPV4(ip, buff, offset);
      } else {
        result = this.toBufferV4(ip, buff, offset);
      }
    } else if (this.isV6Format(ip)) {
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
  static toString(buff: Buffer, offset = 0, length: number = buff.length - offset): IPAddress {
    offset = ~~offset;
    length = length || (buff.length - offset);

    let result = '';
    if (length === 4) {
      // IPv4
      for (let i = 0; i < length; i++) {
        result += ((i > 0) ? '.' : '') + buff[offset + i];
      }
    } else if (length === 16) {
      // IPv6
      for (let i = 0; i < length; i += 2) {
        const word = buff.readUInt16BE(offset + i);
        result += ((i > 0) ? ':' : '') + word.toString(16);
      }
      result = result.replace(/(^|:)0(:0)*:0(:|$)/, '$1::$3');
      result = result.replace(/:{3,4}/, '::');
    }

    return result as IPAddress;
  }

  /**
   * Checks if an IP address is in IPv4 format.
   * @param ip - The IP address to check.
   * @returns True if the IP address is in IPv4 format, false otherwise.
   */
  static isV4Format(ip: IPAddress | string): ip is IPAddress {
    return this.ipv4Regex.test(ip) ||
      this.privateV4Regex.test(ip) ||
      this.loopbackV4Regex.test(ip)
  }

  /**
   * Checks if an IP address is in IPv6 format.
   * @param ip - The IP address to check.
   * @returns True if the IP address is in IPv6 format, false otherwise.
   */
  static isV6Format(ip: IPAddress | string): ip is IPAddress {
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
  private static normalizeFamily(family: IPFamilyNumbers | IPFamilyStrings): IPFamilyStrings {
    return (typeof family === 'number')
      ? `ipv${family}`
      : (family.toLowerCase() as IPFamilyStrings);
  }

  /**
   * Generates an IP address from a prefix length.
   * @param prefixlen - The prefix length.
   * @param family - The IP family (optional, defaults to 'ipv4').
   * @returns The generated IP address.
   */
  static fromPrefixLen(prefixlen: number, family: IPFamily = 'ipv4'): string {
    if (prefixlen > 32) family = 'ipv6';
    if (family !== 'ipv4' && family !== 'ipv6') family = this.normalizeFamily(family);
    if (prefixlen < 0 || (family === 'ipv4' && prefixlen > 32) || (family === 'ipv6' && prefixlen > 128)) {
      throw new Error(`Invalid prefix length: ${prefixlen}`);
    }

    const len = (family === 'ipv4') ? 4 : 16;
    const buff = Buffer.alloc(len);

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
  static mask(addr: IPAddress, mask: IPAddress): IPAddress {
    const addrBuffer = this.toBuffer(addr);
    const maskBuffer = this.toBuffer(mask);

    const result = Buffer.alloc(Math.max(addrBuffer.length, maskBuffer.length));

    let i = 0;
    if (addrBuffer.length === maskBuffer.length) {
      for (i = 0; i < addrBuffer.length; i++) {
        result[i] = addrBuffer[i] & maskBuffer[i];
      }
    } else if (maskBuffer.length === 4) {
      for (i = 0; i < maskBuffer.length; i++) {
        result[i] = addrBuffer[addrBuffer.length - 4 + i] & maskBuffer[i];
      }
    } else {
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
  static cidr(cidrString: string): string {
    const cidrParts = cidrString.split('/');

    if (cidrParts.length !== 2) {
      throw new Error(`Invalid CIDR subnet: ${cidrString}`);
    }

    const addr = cidrParts[0] as IPAddress;
    const mask = this.fromPrefixLen(parseInt(cidrParts[1], 10)) as IPAddress;

    return this.mask(addr, mask);
  }

  /**
   * Applies a mask to an IP address based on a CIDR subnet string.
   * @param cidrString - The CIDR subnet string to apply the mask from.
   * @returns The masked IP address.
   */
  static cidrSubnet(cidrString: string): SubnetRecord {
    const cidrParts = cidrString.split('/');

    if (cidrParts.length !== 2) {
      throw new Error(`Invalid CIDR subnet: ${cidrString}`);
    }

    const addr = cidrParts[0] as IPAddress;
    const mask = this.fromPrefixLen(parseInt(cidrParts[1], 10)) as IPAddress;

    return this.subnet(addr, mask);
  }

  /**
   * Performs a bitwise NOT operation on an IP address.
   * @param addr - The IP address to invert.
   * @returns The inverted IP address.
   */
  static not(addr: IPAddress): string {
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
  static or(a: IPAddress, b: IPAddress): string {
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
  static isEqual(a: IPAddress, b: IPAddress): boolean {
    let aBuffer = this.toBuffer(a);
    let bBuffer = this.toBuffer(b);

    // Same protocol
    if (aBuffer.length === bBuffer.length) {
      for (let i = 0; i < aBuffer.length; i++) {
        if (aBuffer[i] !== bBuffer[i]) return false;
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
      if (bBuffer[i] !== 0) return false;
    }

    const word = bBuffer.readUInt16BE(10);
    if (word !== 0 && word !== 0xffff) return false;


    for (let i = 0; i < 4; i++) {
      if (aBuffer[i] !== bBuffer[i + 12]) return false;
    }

    return true;
  }

  /**
 * Checks if an IP address is a private IPv4 address.
 * @param ip - The IP address to check.
 * @returns True if the IP address is private, false otherwise.
 */
  static isPrivateV4(ip: IPAddress): boolean {
    return this.privateV4Regex.test(ip);
  }

  /**
   * Checks if an IP address is a private IPv6 address.
   * @param ip - The IP address to check.
   * @returns True if the IP address is private, false otherwise.
   */
  static isPrivateV6(ip: IPAddress): boolean {
    return this.ulaV6Regex.test(ip) || this.linkLocalV6Regex.test(ip) || this.loopbackV6Regex.test(ip) || this.unspecifiedV6Regex.test(ip);
  }

  /**
   * Checks if an IP address is a private address.
   * @param addr - The IP address to check.
   * @returns True if the IP address is private, false otherwise.
   */
  static isPrivate(addr: IPAddress): boolean {
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
  static subnet(addr: IPAddress, mask: IPAddress): SubnetRecord {
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
      } else {
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
      contains: (other: IPAddress) => networkAddress === this.toLong(this.mask(other, mask))
    };
  }


  /**
   * Converts an IP address to a long integer representation.
   * 
   * @param ip The IP address to convert.
   * @returns The long integer representation of the IP address.
   */
  static toLong(ip: IPAddress): number {
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
  static fromLong(long: number): IPAddress {
    const ipBuffer = Buffer.alloc(4);

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
  static isPublic(ip: IPAddress): boolean {
    return !this.isPrivate(ip);
  }

  /**
   * Returns the loopback address for the given IP family.
   * @param family - The IP family (optional, defaults to 'ipv4').
   * @returns The loopback address.
   */
  static loopback(family: IPFamily = 'ipv4'): IPAddress {
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
  static isLoopback(ip: IPAddress): ip is IPAddress {
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
  static address(name?: string, family: IPFamily = 'ipv4'): IPAddress | undefined {
    family = this.normalizeFamily(family);
    const interfaces = os.networkInterfaces();

    if (name && name !== 'private' && name !== 'public') {
      const res = interfaces[name]?.filter((details) => {
        const itemFamily = this.normalizeFamily(details.family);
        return itemFamily === family && !this.isLoopback(details.address as IPAddress);
      });
      return (res?.length) ? (res[0].address as IPAddress) : undefined;
    }

    const all = Object.values(interfaces)
      .flatMap((details) => details?.filter((detail) => {
        const itemFamily = this.normalizeFamily(detail.family);
        if (itemFamily !== family || this.isLoopback(detail.address as IPAddress)) return false;

        if (!name) return true;
        return (name === 'public') ? this.isPrivate(detail.address as IPAddress) : this.isPublic(detail.address as IPAddress);
      }))
      .map((detail) => detail?.address);

    return all.length
      ? (all[0] as IPAddress)
      : this.loopback(family);
  }

  static normalizeToLong(addr: IPAddress | string): number {
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

    if (parts.some(Number.isNaN)) return -1; // Indicate error with -1

    let val = 0;
    const n = parts.length;

    switch (n) {
      case 1: [val] = parts; break;
      case 2: {
        if (parts[0] > 0xff || parts[1] > 0xffffff) return -1;
        val = (parts[0] << 24) | (parts[1] & 0xffffff);
        break;
      }
      case 3: {
        if (parts[0] > 0xff || parts[1] > 0xff || parts[2] > 0xffff) return -1;
        val = (parts[0] << 24) | (parts[1] << 16) | (parts[2] & 0xffff);
        break;
      }
      case 4: {
        if (parts.some(part => part > 0xff)) return -1;
        val = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
        break;
      }
      default: return -1; // Error case
    }

    return val >>> 0;
  }
}
