import { expect, suite, test, describe } from 'vitest';
import { Buffer } from 'buffer';
import net from 'net';
import os from 'os';
import ip from '../lib/ip';

suite('IP library for node.js', () => {
  describe('toBuffer()/toString() methods', () => {
    test('should convert to buffer IPv4 address', () => {
      const buf = ip.toBuffer('127.0.0.1');
      expect(buf.toString('hex')).toBe('7f000001');
      expect(ip.toString(buf)).toBe('127.0.0.1');
    });

    test('should convert to buffer IPv4 address in-place', () => {
      const buf = Buffer.alloc(128);
      const offset = 64;
      ip.toBuffer('127.0.0.1', buf, offset);
      expect(buf.toString('hex', offset, offset + 4)).toBe('7f000001');
      expect(ip.toString(buf, offset, 4)).toBe('127.0.0.1');
    });

    test('should convert to buffer IPv6 address', () => {
      const buf = ip.toBuffer('::1');
      expect(/(00){15,15}01/.test(buf.toString('hex'))).toBeTruthy();
      expect(ip.toString(buf)).toBe('::1');
      expect(ip.toString(ip.toBuffer('1::'))).toBe('1::');
      expect(ip.toString(ip.toBuffer('abcd::dcba'))).toBe('abcd::dcba');
    });

    test('should convert to buffer IPv6 address in-place', () => {
      const buf = Buffer.alloc(128);
      const offset = 64;
      ip.toBuffer('::1', buf, offset);
      expect(/(00){15,15}01/.test(buf.toString('hex', offset, offset + 16))).toBeTruthy();
      expect(ip.toString(buf, offset, 16)).toBe('::1');
      expect(ip.toString(ip.toBuffer('1::', buf, offset), offset, 16)).toBe('1::');
      expect(ip.toString(ip.toBuffer('abcd::dcba', buf, offset), offset, 16)).toBe('abcd::dcba');
    });

    test('should convert to buffer IPv6 mapped IPv4 address', () => {
      let buf = ip.toBuffer('::ffff:127.0.0.1');
      expect(buf.toString('hex')).toBe('00000000000000000000ffff7f000001');
      expect(ip.toString(buf)).toBe('::ffff:7f00:1');

      buf = ip.toBuffer('ffff::127.0.0.1');
      expect(buf.toString('hex')).toBe('ffff000000000000000000007f000001');
      expect(ip.toString(buf)).toBe('ffff::7f00:1');

      buf = ip.toBuffer('::ffff:127.0.0.1');
      expect(buf.toString('hex')).toBe('00000000000000000000ffff7f000001');
      expect(ip.toString(buf)).toBe('::ffff:7f00:1');
    });
  });

  describe('fromPrefixLen() method', () => {
    test('should create IPv4 mask', () => {
      expect(ip.fromPrefixLen(24)).toBe('255.255.255.0');
    });
    test('should create IPv6 mask', () => {
      expect(ip.fromPrefixLen(64)).toBe('ffff:ffff:ffff:ffff::');
    });
    test('should create IPv6 mask explicitly', () => {
      expect(ip.fromPrefixLen(24, 'IPV6')).toBe('ffff:ff00::');
    });
  });

  describe('not() method', () => {
    test('should reverse bits in address', () => {
      expect(ip.not('255.255.255.0')).toBe('0.0.0.255');
    });
  });

  describe('or() method', () => {
    test('should or bits in ipv4 addresses', () => {
      expect(ip.or('0.0.0.255', '192.168.1.10')).toBe('192.168.1.255');
    });
    test('should or bits in ipv6 addresses', () => {
      expect(ip.or('::ff', '::abcd:dcba:abcd:dcba')).toBe('::abcd:dcba:abcd:dcff');
    });
    test('should or bits in mixed addresses', () => {
      expect(ip.or('0.0.0.255', '::abcd:dcba:abcd:dcba')).toBe('::abcd:dcba:abcd:dcff');
    });
  });

  describe('mask() method', () => {
    test('should mask bits in address', () => {
      expect(ip.mask('192.168.1.134', '255.255.255.0')).toBe('192.168.1.0');
      expect(ip.mask('192.168.1.134', '::ffff:ff00')).toBe('::ffff:c0a8:100');
    });

    test('should not leak data', () => {
      for (let i = 0; i < 10; i++) {
        expect(ip.mask('::1', '0.0.0.0')).toBe('::');
      }
    });
  });

  describe('subnet() method', () => {
    // Test cases calculated with http://www.subnet-calculator.com/
    const ipv4Subnet = ip.subnet('192.168.1.134', '255.255.255.192');

    test('should compute ipv4 network address', () => {
      expect(ipv4Subnet.networkAddress).toBe('192.168.1.128');
    });

    test('should compute ipv4 network\'s first address', () => {
      expect(ipv4Subnet.firstAddress).toBe('192.168.1.129');
    });

    test('should compute ipv4 network\'s last address', () => {
      expect(ipv4Subnet.lastAddress).toBe('192.168.1.190');
    });

    test('should compute ipv4 broadcast address', () => {
      expect(ipv4Subnet.broadcastAddress).toBe('192.168.1.191');
    });

    test('should compute ipv4 subnet number of addresses', () => {
      expect(ipv4Subnet.length).toBe(64);
    });

    test('should compute ipv4 subnet number of addressable hosts', () => {
      expect(ipv4Subnet.numHosts).toBe(62);
    });

    test('should compute ipv4 subnet mask', () => {
      expect(ipv4Subnet.subnetMask).toBe('255.255.255.192');
    });

    test('should compute ipv4 subnet mask\'s length', () => {
      expect(ipv4Subnet.subnetMaskLength).toBe(26);
    });

    test('should know whether a subnet contains an address', () => {
      expect(ipv4Subnet.contains('192.168.1.180')).toBe(true);
    });

    test('should know whether a subnet does not contain an address', () => {
      expect(ipv4Subnet.contains('192.168.1.195')).toBe(false);
    });
  });

  describe('subnet() method with mask length  32', () => {
    // Test cases calculated with http://www.subnet-calculator.com/
    const ipv4Subnet = ip.subnet('192.168.1.134', '255.255.255.255');
    test('should compute ipv4 network\'s first address', () => {
      expect(ipv4Subnet.firstAddress).toBe('192.168.1.134');
    });

    test('should compute ipv4 network\'s last address', () => {
      expect(ipv4Subnet.lastAddress).toBe('192.168.1.134');
    });

    test('should compute ipv4 subnet number of addressable hosts', () => {
      expect(ipv4Subnet.numHosts).toBe(1);
    });
  });

  describe('subnet() method with mask length  31', () => {
    // Test cases calculated with http://www.subnet-calculator.com/
    const ipv4Subnet = ip.subnet('192.168.1.134', '255.255.255.254');
    test('should compute ipv4 network\'s first address', () => {
      expect(ipv4Subnet.firstAddress).toBe('192.168.1.134');
    });

    test('should compute ipv4 network\'s last address', () => {
      expect(ipv4Subnet.lastAddress).toBe('192.168.1.135');
    });

    test('should compute ipv4 subnet number of addressable hosts', () => {
      expect(ipv4Subnet.numHosts).toBe(2);
    });
  });

  describe('cidrSubnet() method', () => {
    // Test cases calculated with http://www.subnet-calculator.com/
    const ipv4Subnet = ip.cidrSubnet('192.168.1.134/26');

    test('should compute an ipv4 network address', () => {
      expect(ipv4Subnet.networkAddress).toBe('192.168.1.128');
    });

    test('should compute an ipv4 network\'s first address', () => {
      expect(ipv4Subnet.firstAddress).toBe('192.168.1.129');
    });

    test('should compute an ipv4 network\'s last address', () => {
      expect(ipv4Subnet.lastAddress).toBe('192.168.1.190');
    });

    test('should compute an ipv4 broadcast address', () => {
      expect(ipv4Subnet.broadcastAddress).toBe('192.168.1.191');
    });

    test('should compute an ipv4 subnet number of addresses', () => {
      expect(ipv4Subnet.length).toBe(64);
    });

    test('should compute an ipv4 subnet number of addressable hosts', () => {
      expect(ipv4Subnet.numHosts).toBe(62);
    });

    test('should compute an ipv4 subnet mask', () => {
      expect(ipv4Subnet.subnetMask).toBe('255.255.255.192');
    });

    test('should compute an ipv4 subnet mask\'s length', () => {
      expect(ipv4Subnet.subnetMaskLength).toBe(26);
    });

    test('should know whether a subnet contains an address', () => {
      expect(ipv4Subnet.contains('192.168.1.180')).toBe(true);
    });

    test('should know whether a subnet contains an address', () => {
      expect(ipv4Subnet.contains('192.168.1.195')).toBe(false);
    });
  });

  describe('cidr() method', () => {
    test('should mask address in CIDR notation', () => {
      expect(ip.cidr('192.168.1.134/26')).toBe('192.168.1.128');
      expect(ip.cidr('2607:f0d0:1002:51::4/56')).toBe('2607:f0d0:1002::');
    });
  });

  describe('isEqual() method', () => {
    test('should check if addresses are equal', () => {
      expect(ip.isEqual('127.0.0.1', '::7f00:1')).toBe(true);
      expect(ip.isEqual('127.0.0.1', '::7f00:2')).toBe(false);
      expect(ip.isEqual('127.0.0.1', '::ffff:7f00:1')).toBe(true);
      expect(ip.isEqual('127.0.0.1', '::ffaf:7f00:1')).toBe(false);
      expect(ip.isEqual('::ffff:127.0.0.1', '::ffff:127.0.0.1')).toBe(true);
      expect(ip.isEqual('::ffff:127.0.0.1', '127.0.0.1')).toBe(true);
    });
  });

  describe('normalizeIpv4() method', () => {
    // Testing valid inputs with different notations
    test('should correctly normalize "127.0.0.1"', () => {
      expect(ip.normalizeToLong('127.0.0.1')).toBe(2130706433);
    });

    test('should correctly handle "127.1" as two parts', () => {
      expect(ip.normalizeToLong('127.1')).toBe(2130706433);
    });

    test('should correctly handle "127.0.1" as three parts', () => {
      expect(ip.normalizeToLong('127.0.1')).toBe(2130706433);
    });

    test('should correctly handle hexadecimal notation "0x7f.0x0.0x0.0x1"', () => {
      expect(ip.normalizeToLong('0x7f.0x0.0x0.0x1')).toBe(2130706433);
    });

    // Testing with fewer than  4 parts
    test('should correctly handle "0x7f000001" as a single part', () => {
      expect(ip.normalizeToLong('0x7f000001')).toBe(2130706433);
    });

    test('should correctly handle octal notation "010.0.0.01"', () => {
      expect(ip.normalizeToLong('010.0.0.01')).toBe(134217729);
    });

    // Testing invalid inputs
    test('should return -1 for an invalid address "256.100.50.25"', () => {
      expect(ip.normalizeToLong('256.100.50.25')).toBe(-1);
    });

    test('should return -1 for an address with invalid octal "019.0.0.1"', () => {
      expect(ip.normalizeToLong('019.0.0.1')).toBe(-1);
    });

    test('should return -1 for an address with invalid hex "0xGG.0.0.1"', () => {
      expect(ip.normalizeToLong('0xGG.0.0.1')).toBe(-1);
    });

    // Testing edge cases
    test('should return -1 for an empty string', () => {
      expect(ip.normalizeToLong('')).toBe(-1);
    });

    test('should return -1 for a string with too many parts "192.168.0.1.100"', () => {
      expect(ip.normalizeToLong('192.168.0.1.100')).toBe(-1);
    });
  });

  describe('isPrivate() method', () => {
    test('should check if an address is localhost', () => {
      expect(ip.isPrivate('127.0.0.1')).toBe(true);
    });

    test('should check if an address is from a  192.168.x.x network', () => {
      expect(ip.isPrivate('192.168.0.123')).toBe(true);
      expect(ip.isPrivate('192.168.122.123')).toBe(true);
      expect(ip.isPrivate('192.162.1.2')).toBe(false);
    });

    test('should check if an address is from a  172.16.x.x network', () => {
      expect(ip.isPrivate('172.16.0.5')).toBe(true);
      expect(ip.isPrivate('172.16.123.254')).toBe(true);
      expect(ip.isPrivate('171.16.0.5')).toBe(false);
      expect(ip.isPrivate('172.25.232.15')).toBe(true);
      expect(ip.isPrivate('172.15.0.5')).toBe(false);
      expect(ip.isPrivate('172.32.0.5')).toBe(false);
    });

    test('should check if an address is from a   169.254.x.x network', () => {
      expect(ip.isPrivate('169.254.2.3')).toBe(true);
      expect(ip.isPrivate('169.254.221.9')).toBe(true);
      expect(ip.isPrivate('168.254.2.3')).toBe(false);
    });

    test('should check if an address is from a   10.x.x.x network', () => {
      expect(ip.isPrivate('10.0.2.3')).toBe(true);
      expect(ip.isPrivate('10.1.23.45')).toBe(true);
      expect(ip.isPrivate('12.1.2.3')).toBe(false);
    });

    test('should check if an address is from a private IPv6 network', () => {
      expect(ip.isPrivate('fd12:3456:789a:1::1')).toBe(true);
      expect(ip.isPrivate('fe80::f2de:f1ff:fe3f:307e')).toBe(true);
      expect(ip.isPrivate('::ffff:10.100.1.42')).toBe(true);
      expect(ip.isPrivate('::FFFF:172.16.200.1')).toBe(true);
      expect(ip.isPrivate('::ffff:192.168.0.1')).toBe(true);
    });

    test('should check if an address is from the internet', () => {
      expect(ip.isPrivate('165.225.132.33')).toBe(false); // joyent.com
    });

    test('should check if an address is a loopback IPv6 address', () => {
      expect(ip.isPrivate('::')).toBe(true);
      expect(ip.isPrivate('::1')).toBe(true);
      expect(ip.isPrivate('fe80::1')).toBe(true);
    });

    test('should correctly identify hexadecimal IP addresses like \'0x7f.1\' as private', () => {
      expect(ip.isPrivate('0x7f.1')).toBe(true);
    });
  });

  describe('loopback() method', () => {
    describe('undefined', () => {
      test('should respond with  127.0.0.1', () => {
        expect(ip.loopback()).toBe('127.0.0.1');
      });
    });

    describe('ipv4', () => {
      test('should respond with  127.0.0.1', () => {
        expect(ip.loopback('ipv4')).toBe('127.0.0.1');
      });
    });

    describe('ipv6', () => {
      test('should respond with fe80::1', () => {
        expect(ip.loopback('ipv6')).toBe('fe80::1');
      });
    });
  });

  describe('isLoopback() method', () => {
    describe('127.0.0.1', () => {
      test('should respond with true', () => {
        expect(ip.isLoopback('127.0.0.1')).toBe(true);
      });
    });

    describe('127.8.8.8', () => {
      test('should respond with true', () => {
        expect(ip.isLoopback('127.8.8.8')).toBe(true);
      });
    });

    describe('8.8.8.8', () => {
      test('should respond with false', () => {
        expect(ip.isLoopback('8.8.8.8')).toBe(false);
      });
    });

    describe('fe80::1', () => {
      test('should respond with true', () => {
        expect(ip.isLoopback('fe80::1')).toBe(true);
      });
    });

    describe('::1', () => {
      test('should respond with true', () => {
        expect(ip.isLoopback('::1')).toBe(true);
      });
    });

    describe('::', () => {
      test('should respond with true', () => {
        expect(ip.isLoopback('::')).toBe(true);
      });
    });
  });

  describe('address() method', () => {
    describe('undefined', () => {
      test('should respond with a private ip', () => {
        const thisIP = ip.address()!;
        expect(ip.isPrivate(thisIP)).toBe(true);
      });
    });

    describe('private', () => {
      [undefined, 'ipv4', 'ipv6'].forEach((family) => {
        describe(family ?? 'undefined', () => {
          test('should respond with a private ip', () => {
            // @ts-expect-error
            expect(ip.isPrivate(ip.address('private', family))).toBe(true);
          });
        });
      });
    });

    const interfaces = os.networkInterfaces();

    Object.keys(interfaces).forEach((nic) => {
      describe(nic, () => {
        [undefined, 'ipv4'].forEach((family) => {
          describe(family ?? 'undefined', () => {
            test('should respond with an ipv4 address', () => {
              // @ts-expect-error
              const addr = ip.address(nic, family);
              expect(!addr || net.isIPv4(addr)).toBe(true);
            });
          });
        });

        describe('ipv6', () => {
          test('should respond with an ipv6 address', () => {
            const addr = ip.address(nic, 'ipv6');
            expect(!addr || net.isIPv6(addr)).toBe(true);
          });
        });
      });
    });
  });

  describe('toLong() method', () => {
    test('should respond with a int', () => {
      expect(ip.toLong('127.0.0.1')).toBe(2130706433);
      expect(ip.toLong('255.255.255.255')).toBe(4294967295);
    });
  });

  describe('fromLong() method', () => {
    test('should respond with ipv4 address', () => {
      expect(ip.fromLong(2130706433)).toBe('127.0.0.1');
      expect(ip.fromLong(4294967295)).toBe('255.255.255.255');
    });
  });

  describe('Octal/Hexadecimal Representations', () => {
    // IPv4 loopback in octal notation
    test('should return true for octal representation "0177.0.0.1"', () => {
      expect(ip.isLoopback('0177.0.0.1')).toBe(true);
    });

    test('should return true for octal representation "0177.0.1"', () => {
      expect(ip.isLoopback('0177.0.1')).toBe(true);
    });

    test('should return true for octal representation "0177.1"', () => {
      expect(ip.isLoopback('0177.1')).toBe(true);
    });

    // IPv4 loopback in hexadecimal notation
    test('should return true for hexadecimal representation "0x7f.0.0.1"', () => {
      expect(ip.isLoopback('0x7f.0.0.1')).toBe(true);
    });

    // IPv4 loopback in hexadecimal notation
    test('should return true for hexadecimal representation "0x7f.0.1"', () => {
      expect(ip.isLoopback('0x7f.0.1')).toBe(true);
    });

    // IPv4 loopback in hexadecimal notation
    test('should return true for hexadecimal representation "0x7f.1"', () => {
      expect(ip.isLoopback('0x7f.1')).toBe(true);
    });

    // IPv4 loopback as a single long integer
    test('should return true for single long integer representation "2130706433"', () => {
      expect(ip.isLoopback('2130706433')).toBe(true);
    });

    // IPv4 non-loopback address
    test('should return false for "192.168.1.1"', () => {
      expect(ip.isLoopback('192.168.1.1')).toBe(false);
    });
  })
});

