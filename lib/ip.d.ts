/// <reference types="node" />
import { Buffer } from 'node:buffer';
type IPAddress = `${number}.${number}.${number}.${number}` | `${string}:${string}:${string}:${string}:${string}:${string}:${string}:${string}` | `${string | number}:${string | number}:${string | number}:${string | number}:${string | number}:${string | number}` | `${string | number}:${string | number}:${string | number}:${string | number}` | `${string | number}:${string | number}:${string | number}` | `::${number}.${number}.${number}.${number}` | `::${number}.${number}.${number}` | `::${number}.${number}` | `::${number}` | `::${string}` | '::' | `0x${string}` | `${number}` | `0${number}.${number}.${number}`;
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
}
/**
 * IP utility class providing static methods for IP address manipulation.
 */
export default class IP {
    private static readonly ipv4Regex;
    /** Regular expression for matching IPv6 addresses that are mapped from IPv4 addresses */
    private static readonly ipv4MappedV6Regex;
    /** Regular expression for matching IPv6 addresses */
    private static readonly ipv6Regex;
    /** Regular expression for matching Unique Local Addresses (ULAs) */
    private static readonly ulaV6Regex;
    /** Regular expression for matching link-local IPv6 addresses */
    private static readonly linkLocalV6Regex;
    /** Regular expression for matching any unspecified IPv6 address */
    private static readonly unspecifiedV6Regex;
    /** Regular expression for matching private IPv4 addresses */
    private static readonly privateV4Regex;
    /** Regular expression for matching private IPv6 addresses that are mapped from IPv4 addresses */
    private static readonly privateV4MappedV6Regex;
    /** Regular expression for matching loopback IPv6 addresses */
    private static readonly loopbackV6Regex;
    /** Regular expression for matching IPv4 loopback addresses */
    private static readonly loopbackV4Regex;
    /** Regular Expression for matching loopback IPv4 addresses starting with 0177 */
    private static readonly loopbackV4_0177;
    /** Regular Expression for matching hexadecimal loopback IPv4 addresses */
    private static readonly loopbackV4_hex;
    /**
     * Converts an IPv4 address to a Buffer.
     * @param {IPAddress} ip - The IPv4 address to convert.
     * @param {Buffer} buff - An optional Buffer to write the result to.
     * @param {number} offset - The offset in the Buffer to start writing at.
     * @returns {Buffer} The Buffer containing the IPv4 address.
     */
    private static toBufferV4;
    /**
     * Converts an IPv6 address to a Buffer.
     * @param {IPAddress} ip - The IPv6 address to convert.
     * @param {Buffer} buff - An optional Buffer to write the result to.
     * @param {number} offset - The offset in the Buffer to start writing at.
     * @returns {Buffer} The Buffer containing the IPv6 address.
     */
    private static toBufferV6;
    private static toBufferIPV6MappedIPV4;
    /**
     * Converts an IP address to a Buffer.
     * @param {IPAddress} ip - The IP address to convert.
     * @param {Buffer} buff - An optional Buffer to write the result to.
     * @param {number} offset - The offset in the Buffer to start writing at.
     * @returns {Buffer} The Buffer containing the IP address.
     */
    static toBuffer(ip: IPAddress | string, buff?: Buffer, offset?: number): Buffer;
    /**
     * Converts a Buffer to an IP address string.
     * @param buff - The Buffer containing the IP address.
     * @param offset - The offset in the Buffer to start reading from.
     * @param length - The length of the IP address in the Buffer.
     * @returns The IP address string.
     */
    static toString(buff: Buffer, offset?: number, length?: number): IPAddress;
    /**
     * Checks if an IP address is in IPv4 format.
     * @param ip - The IP address to check.
     * @returns True if the IP address is in IPv4 format, false otherwise.
     */
    static isV4Format(ip: IPAddress | string): ip is IPAddress;
    /**
     * Checks if an IP address is in IPv6 format.
     * @param ip - The IP address to check.
     * @returns True if the IP address is in IPv6 format, false otherwise.
     */
    static isV6Format(ip: IPAddress | string): ip is IPAddress;
    /**
     * Normalizes the family parameter to either 'ipv4' or 'ipv6'.
     * @param family - The family parameter to normalize.
     * @returns The normalized family parameter.
     */
    private static normalizeFamily;
    /**
     * Generates an IP address from a prefix length.
     * @param prefixlen - The prefix length.
     * @param family - The IP family (optional, defaults to 'ipv4').
     * @returns The generated IP address.
     */
    static fromPrefixLen(prefixlen: number, family?: IPFamily): string;
    /**
     * Applies a mask to an IP address.
     * @param addr - The IP address to mask.
     * @param mask - The mask to apply.
     * @returns The masked IP address.
     */
    static mask(addr: IPAddress, mask: IPAddress): IPAddress;
    /**
   * Applies a mask to an IP address based on a CIDR string.
   * @param cidrString - The CIDR string to apply the mask from.
   * @returns The masked IP address.
   */
    static cidr(cidrString: string): string;
    /**
     * Applies a mask to an IP address based on a CIDR subnet string.
     * @param cidrString - The CIDR subnet string to apply the mask from.
     * @returns The masked IP address.
     */
    static cidrSubnet(cidrString: string): SubnetRecord;
    /**
     * Performs a bitwise NOT operation on an IP address.
     * @param addr - The IP address to invert.
     * @returns The inverted IP address.
     */
    static not(addr: IPAddress): string;
    /**
     * Performs a bitwise OR operation on two IP addresses.
     * @param a - The first IP address.
     * @param b - The second IP address.
     * @returns The result of the bitwise OR operation.
     */
    static or(a: IPAddress, b: IPAddress): string;
    /**
     * Checks if two IP addresses are equal.
     * @param a - The first IP address.
     * @param b - The second IP address.
     * @returns True if the IP addresses are equal, false otherwise.
     */
    static isEqual(a: IPAddress, b: IPAddress): boolean;
    /**
   * Checks if an IP address is a private IPv4 address.
   * @param ip - The IP address to check.
   * @returns True if the IP address is private, false otherwise.
   */
    static isPrivateV4(ip: IPAddress): boolean;
    /**
     * Checks if an IP address is a private IPv6 address.
     * @param ip - The IP address to check.
     * @returns True if the IP address is private, false otherwise.
     */
    static isPrivateV6(ip: IPAddress): boolean;
    /**
     * Checks if an IP address is a private address.
     * @param addr - The IP address to check.
     * @returns True if the IP address is private, false otherwise.
     */
    static isPrivate(addr: IPAddress): boolean;
    /**
   * Calculates the subnet details for a given IP address and mask.
   * @param addr - The IP address.
   * @param mask - The subnet mask.
   * @returns An object containing the subnet details.
   */
    static subnet(addr: IPAddress, mask: IPAddress): SubnetRecord;
    /**
     * Converts an IP address to a long integer representation.
     *
     * @param ip The IP address to convert.
     * @returns The long integer representation of the IP address.
     */
    static toLong(ip: IPAddress): number;
    /**
     * Converts a long integer to an IP address.
     * @param long - The long integer to convert.
     * @returns The IP address string.
     */
    static fromLong(long: number): IPAddress;
    /**
     * Checks if an IP address is a public address.
     * @param ip - The IP address to check.
     * @returns True if the IP address is public, false otherwise.
     */
    static isPublic(ip: IPAddress): boolean;
    /**
     * Returns the loopback address for the given IP family.
     * @param family - The IP family (optional, defaults to 'ipv4').
     * @returns The loopback address.
     */
    static loopback(family?: IPFamily): IPAddress;
    /**
     * Checks if an IP address is a loopback address.
     * @param ip - The IP address to check.
     * @returns True if the IP address is a loopback address, false otherwise.
     */
    static isLoopback(ip: IPAddress): ip is IPAddress;
    /**
     * Returns the address for the network interface on the current system with the specified `name`.
     * @param name - The name or security of the network interface.
     * @param family - The IP family of the address (defaults to 'ipv4').
     * @returns The address for the network interface.
     */
    static address(name?: string, family?: IPFamily): IPAddress | undefined;
    static normalizeToLong(addr: IPAddress | string): number;
}
export {};
