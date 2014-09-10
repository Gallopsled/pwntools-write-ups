#!/usr/bin/env python2
from struct import pack,unpack

# Poly in "reversed" notation -- http://en.wikipedia.org/wiki/Cyclic_redundancy_check
POLY = 0xedb88320 # CRC-32-IEEE 802.3
#POLY = 0x82F63B78 # CRC-32C (Castagnoli)
#POLY = 0xEB31D82E # CRC-32K (Koopman)
#POLY = 0xD5828281 # CRC-32Q

def build_crc_tables():
    for i in range(256):
        fwd = i
        rev = i << 24
        for j in range(8, 0, -1):
            # build normal table
            if (fwd & 1) == 1:
                fwd = (fwd >> 1) ^ POLY
            else:
                fwd >>= 1
            crc32_table[i] = fwd & 0xffffffff
            # build reverse table =)
            if rev & 0x80000000 == 0x80000000:
                rev = ((rev ^ POLY) << 1) | 1
            else:
                rev <<= 1
            rev &= 0xffffffff
            crc32_reverse[i] = rev

crc32_table, crc32_reverse = [0]*256, [0]*256
build_crc_tables()

def crc32(s): # same crc32 as in (binascii.crc32)&0xffffffff
  crc = 0 #0xffffffff
  for c in s:
    crc = (crc >> 8) ^ crc32_table[(crc ^ ord(c)) & 0xff]
  return crc #^0xffffffff

def forge(wanted_crc, str, pos=None):
  if pos is None:
    pos = len(str)

  # forward calculation of CRC up to pos, sets current forward CRC state
  fwd_crc = 0 # <<<< PATCHED!
  for c in str[:pos]:
    fwd_crc = (fwd_crc >> 8) ^ crc32_table[(fwd_crc ^ ord(c)) & 0xff]

  # backward calculation of CRC up to pos, sets wanted backward CRC state
  bkd_crc = wanted_crc #^0xffffffff # <<<< PATCHED!
  for c in str[pos:][::-1]:
    bkd_crc = ((bkd_crc << 8)&0xffffffff) ^ crc32_reverse[bkd_crc >> 24] ^ ord(c)

  # deduce the 4 bytes we need to insert
  for c in pack('<L',fwd_crc)[::-1]:
    bkd_crc = ((bkd_crc << 8)&0xffffffff) ^ crc32_reverse[bkd_crc >> 24] ^ ord(c)

  res = str[:pos] + pack('<L', bkd_crc) + str[pos:]
  assert(crc32(res) == wanted_crc)
  return res