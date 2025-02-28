#!/usr/bin/env python3
#
# Simple LZH archive extractor -- unlha.py
# Python version copyright (c) 2024 Yuichi Nakamura (@yunkya2)
#  URL: https://github.com/yunkay2/unlha
#  LICENSE condition: https://github.com/yunkay2/unlha/blob/main/LICENSE
# ----------------------------------------------------------------
# This software is derived from "LHa for UNIX with Autoconf"
#
# LHarc    for UNIX  V 1.02  Copyright(C) 1989  Y.Tagawa
# LHx      for MSDOS V C2.01 Copyright(C) 1990  H.Yoshizaki
# LHx(arc) for OSK   V 2.01  Modified     1990  Momozou
# LHa      for UNIX  V 1.00  Copyright(C) 1992  Masaru Oki
# LHa      for UNIX  V 1.14  Modified     1995  Nobutaka Watazaki
# LHa      for UNIX  V 1.14i Modified     2000  Tsugio Okamoto
# LHA-PMA  for UNIX  V 2     PMA added    2000  Maarten ter Huurne
#                    Autoconfiscated 2001-2008  Koji Arai
#

import os
import sys
import stat
import time
import struct

##############################################################################

class BitIo:
    """Bit stream input (from bito.c)"""
    CHAR_BIT = 8

    def __init__(self, fh, compsize):
        self.fh = fh
        self.bitbuf = 0
        self.subbitbuf = 0
        self.bitcount = 0
        self.compsize = compsize
        self.fillbuf(2 * self.CHAR_BIT)

    def peekbits(self,n):
        x = self.bitbuf >> (2 * self.CHAR_BIT - n)
        return x

    def getbits(self, n):
        x = self.peekbits(n)
        self.fillbuf(n)
        return x

    def fillbuf(self, n):
        while n > self.bitcount:
            n -= self.bitcount
            self.bitbuf = (self.bitbuf << self.bitcount) & 0xffff
            self.bitbuf += (self.subbitbuf) >> (self.CHAR_BIT - self.bitcount)
            if self.compsize != 0:
                self.compsize -= 1
                if not (c := self.fh.read(1)):
                    self.compsize = 0
                    c = b'\0'
                    raise RuntimeError("cannot read stream");
                self.subbitbuf = ord(c)
            else:
                self.subbitbuf = 0
            self.bitcount = self.CHAR_BIT
        self.bitcount -= n
        self.bitbuf = (self.bitbuf << n) & 0xffff
        self.bitbuf |= (self.subbitbuf) >> (self.CHAR_BIT - n)
        self.subbitbuf = (self.subbitbuf << n) & 0xff

##############################################################################

class CrcIo:
    """CRC calculation (from crcio.c)"""
    CRCPOLY = 0xa001        # CRC-16 (X^16 + X^15 + X^2 + 1)

    def __init__(self):
        self.crctable = [0] * 256
        for i in range(256):
            r = i
            for _ in range(8):
                if r & 1:
                    r = (r >> 1) ^ self.CRCPOLY
                else:
                    r >>= 1
            self.crctable[i] = r

    def calccrc(self, crc, p, n):
        for i in range(n):
            crc = self.crctable[(crc ^ p[i]) & 0xff] ^ (crc >> 8)
        return crc        

##############################################################################

class LzhHeader:
    """LZH header operation (from header.c)"""
    I_HEADER_SIZE           = 0
    I_HEADER_CHECKSUM       = 1
    I_METHOD                = 2
    I_PACKED_SIZE           = 7
    I_ATTRIBUTE             = 19
    I_HEADER_LEVEL          = 20

    COMMON_HEADER_SIZE      = 21

    I_GENERIC_HEADER_SIZE   = 24
    I_LEVEL0_HEADER_SIZE    = 36
    I_LEVEL1_HEADER_SIZE    = 27
    I_LEVEL2_HEADER_SIZE    = 26
    I_LEVEL3_HEADER_SIZE    = 32

    def __init__(self):
        self.header_size = self.COMMON_HEADER_SIZE
        self.crcio = CrcIo()

    def calc_sum(self, buf):
        sum = 0
        for byte in buf:
            sum += byte
        return sum & 0xff

    def generic_to_unix_timestamp(self, t):
        def subbits(n, off, len):
            return (n >> off) & ((1 << len) - 1)
        tm = (subbits(t, 25, 7) + 1980, \
              subbits(t, 21, 4), \
              subbits(t, 16, 5), \
              subbits(t, 11, 5), \
              subbits(t,  5, 6), \
              subbits(t,  0, 5) * 2, \
              0, 0, 0)
        return time.mktime(tm)

    def get_header(self, fh):
        self.fh = fh
        self.name = b''
        self.has_crc = False

        buf = fh.read(self.COMMON_HEADER_SIZE)
        if len(buf) < self.COMMON_HEADER_SIZE:
            return None

        self.header_level = buf[self.I_HEADER_LEVEL]
        if self.header_level == 0:
            res = self.get_header_level0(fh, buf)
        elif self.header_level == 1:
            res = self.get_header_level1(fh, buf)
        elif self.header_level == 2:
            res =  self.get_header_level2(fh, buf)
#        elif self.header_level == 3:
#            res =  self.get_header_level3(fh, buf)
        else:
            raise RuntimeError(f"unknown header level {self.header_level}")

        if not res:
            return None

        if self.name[0] == 0xff:
            self.name = self.name[1:]
        self.name = self.name.replace(b'\377', b'/')
        try:
            self.name = self.name.decode('cp932')
        except UnicodeDecodeError:
            try:
                self.name = self.name.decode()
            except UnicodeDecodeError:
                pass

        return True

    def get_header_level0(self, fh, buf):
        #
        # level 0 header
        #
        #
        # offset  size  field name
        # ----------------------------------
        #     0      1  header size    [*1]
        #     1      1  header sum
        #            ---------------------------------------
        #     2      5  method ID                         ^
        #     7      4  packed size    [*2]               |
        #    11      4  original size                     |
        #    15      2  time                              |
        #    17      2  date                              |
        #    19      1  attribute                         | [*1] header size (X+Y+22)
        #    20      1  level (0x00 fixed)                |
        #    21      1  name length                       |
        #    22      X  pathname                          |
        # X +22      2  file crc (CRC-16)                 |
        # X +24      Y  ext-header(old style)             v
        # -------------------------------------------------
        # X+Y+24        data                              ^
        #                 :                               | [*2] packed size
        #                 :                               v
        # -------------------------------------------------
        #
        # ext-header(old style)
        #     0      1  ext-type ('U')
        #     1      1  minor version
        #     2      4  UNIX time
        #     6      2  mode
        #     8      2  uid
        #    10      2  gid
        #
        # attribute (MS-DOS)
        #    bit1  read only
        #    bit2  hidden
        #    bit3  system
        #    bit4  volume label
        #    bit5  directory
        #    bit6  archive bit (need to backup)
        #
        self.size_field_length = 2
        self.header_size = buf[0]
        checksum = buf[1]
        buf = buf + fh.read(self.header_size + 2 - self.COMMON_HEADER_SIZE)
        if len(buf) != self.header_size + 2:
            raise RuntimeError("Invalid header size")

        p = self.I_METHOD
        if self.calc_sum(buf[p:]) != checksum:
            raise RuntimeError("Checksum error")

        self.method = buf[p:p+5]
        p += 5
        (self.packed_size, self.original_size, ts, self.attribute, self.header_level, name_length) = \
            struct.unpack("<3I3B", buf[p:p+15])
        self.unix_last_modified_stamp = self.generic_to_unix_timestamp(ts)
        p += 15
        self.name = buf[p:p+name_length]
        p += name_length

        self.unix_mode = stat.S_IRUSR|stat.S_IWUSR|stat.S_IRGRP|stat.S_IWGRP|stat.S_IROTH|stat.S_IWOTH
        self.unix_gid = 0
        self.unix_uid = 0

        self.extend_size = self.header_size + 2 - name_length - 24

        if self.extend_size < 0:
            if self.extend_size == -2:
                # CRC field is not given
                self.extend_type = 0
                self.has_crc = False
                return True
            raise RuntimeError("Unknown header")

        self.has_crc = True
        (self.crc,) = struct.unpack('<H', buf[p:p+2])
        p += 2

        if self.extend_size != 0:
            self.extend_type = buf[p]
            p += 1
            self.extend_size -= 1

            if self.extend_type == ord('U'):
                if self.extend_size >= 11:
                    (self.minor_version, self.unix_last_modified_stamp, \
                     self.unix_mode, self.unix_uid, self.unix_gid) = struct.unpack('<BI3H', buf[p:p+11])
                    p += 11
                    self.extend_size -= 11
                else:
                    self.extend_type = 0

        self.header_size += 2
        return True

    def get_header_level1(self, fh, buf):
        #
        # level 1 header
        #
        #
        # offset   size  field name
        # -----------------------------------
        #     0       1  header size   [*1]
        #     1       1  header sum
        #             -------------------------------------
        #     2       5  method ID                        ^
        #     7       4  skip size     [*2]               |
        #    11       4  original size                    |
        #    15       2  time                             |
        #    17       2  date                             |
        #    19       1  attribute (0x20 fixed)           | [*1] header size (X+Y+25)
        #    20       1  level (0x01 fixed)               |
        #    21       1  name length                      |
        #    22       X  filename                         |
        # X+ 22       2  file crc (CRC-16)                |
        # X+ 24       1  OS ID                            |
        # X +25       Y  ???                              |
        # X+Y+25      2  next-header size                 v
        # -------------------------------------------------
        # X+Y+27      Z  ext-header                       ^
        #                 :                               |
        # -----------------------------------             | [*2] skip size
        # X+Y+Z+27       data                             |
        #                 :                               v
        # -------------------------------------------------
        #
        self.size_field_length = 2
        self.header_size = buf[0]
        checksum = buf[1]
        buf = buf + fh.read(self.header_size + 2 - self.COMMON_HEADER_SIZE)
        if len(buf) != self.header_size + 2:
            raise RuntimeError("Invalid header size")

        p = self.I_METHOD
        if self.calc_sum(buf[p:]) != checksum:
            raise RuntimeError("Checksum error")

        self.method = buf[p:p+5]
        p += 5
        (self.packed_size, self.original_size, ts, self.attribute, self.header_level, name_length) = \
            struct.unpack("<3I3B", buf[p:p+15])
        self.unix_last_modified_stamp = self.generic_to_unix_timestamp(ts)
        p += 15
        self.name = buf[p:p+name_length]
        p += name_length

        self.unix_mode = stat.S_IRUSR|stat.S_IWUSR|stat.S_IRGRP|stat.S_IWGRP|stat.S_IROTH|stat.S_IWOTH
        self.unix_gid = 0
        self.unix_uid = 0

        self.has_crc = True
        (self.crc, self.extend_type) = struct.unpack('<HB', buf[p:p+3])

        (self.extend_size,) = struct.unpack('<H', buf[-2:])
        (self.extend_size, hcrc) = self.get_extended_header(self.extend_size)

        self.packed_size -= self.extend_size
        self.header_size += self.extend_size
        self.header_size += 2
        return True

    def get_header_level2(self, fh, buf):
        #
        # level 2 header
        #
        #
        # offset   size  field name
        # --------------------------------------------------
        #     0       2  total header size [*1]           ^
        #             -----------------------             |
        #     2       5  method ID                        |
        #     7       4  packed size       [*2]           |
        #    11       4  original size                    |
        #    15       4  time                             |
        #    19       1  RESERVED (0x20 fixed)            | [*1] total header size
        #    20       1  level (0x02 fixed)               |      (X+26+(1))
        #    21       2  file crc (CRC-16)                |
        #    23       1  OS ID                            |
        #    24       2  next-header size                 |
        # -----------------------------------             |
        #    26       X  ext-header                       |
        #                 :                               |
        # -----------------------------------             |
        # X +26      (1) padding                          v
        # -------------------------------------------------
        # X +26+(1)      data                             ^
        #                 :                               | [*2] packed size
        #                 :                               v
        # -------------------------------------------------
        #
        self.size_field_length = 2
        (self.header_size,) = struct.unpack("<H", buf[0:2])

        buf = buf + fh.read(self.I_LEVEL2_HEADER_SIZE - self.COMMON_HEADER_SIZE)
        if len(buf) != self.I_LEVEL2_HEADER_SIZE:
            raise RuntimeError("Invalid header size")

        p = self.I_METHOD
        self.method = buf[p:p+5]
        p += 5
        (self.packed_size, self.original_size, self.unix_last_modified_stamp, \
         self.attribute, self.header_level) = struct.unpack("<3I2B", buf[p:p+14])
        p += 14

        self.unix_mode = stat.S_IRUSR|stat.S_IWUSR|stat.S_IRGRP|stat.S_IWGRP|stat.S_IROTH|stat.S_IWOTH
        self.unix_gid = 0
        self.unix_uid = 0

        self.has_crc = True
        (self.crc, self.extend_type, self.extend_size) = struct.unpack('<HBH', buf[p:p+5])

        hcrc = self.crcio.calccrc(0, buf, p + 5)
        (self.extend_size, hcrc) = self.get_extended_header(self.extend_size, hcrc)

        padding = self.header_size - self.I_LEVEL2_HEADER_SIZE - self.extend_size
        if padding != 0 and padding != 1:
            raise RuntimeError(f"Invalid header size (padding: {padding})")

        if self.header_crc != hcrc:
            raise RuntimeError("header CRC error")

        return True

    def get_extended_header(self, header_size, crc=0):
        whole_size = header_size
        n = 1 + self.size_field_length
        if self.header_level == 0:
            return (0, 0)
        
        name_length = len(self.name)
        dir_length = 0
        dirname=b'\0'

        while header_size:
            buf = self.fh.read(header_size)
            if len(buf) != header_size:
                raise RuntimeError("Invalid header")

            ext_type = buf[0]
            if ext_type == 0x00:        # header crc
                (self.header_crc,) = struct.unpack('<H', buf[1:3])
                buf = bytearray(buf)
                buf[1:3] = [0, 0]
            elif ext_type == 0x01:      # filename
                name_length = header_size - n
                self.name = buf[1:1+name_length]
            elif ext_type == 0x02:      # directory
                dir_length = header_size - n
                dirname = buf[1:1+dir_length]
            elif ext_type == 0x40:      # MS_DOS attribute
                (self.attribute,) = struct.unpack('<H', buf[1:1+2])
            elif ext_type == 0x42:      # 64bits file size header
                (self.packed_size, self.original_size) = struct.unpack('<2Q', buf[1:1+16])
            elif ext_type == 0x50:      # UNIX permission
                (self.unix_mode,) = struct.unpack('<H', buf[1:1+2])
            elif ext_type == 0x51:      # UNIX gid and uid
                (self.unix_gid, self.unix_uid) = struct.unpack('<2H', buf[1:1+4])
            elif ext_type == 0x54:      # UNIX last modified time
                (self.unix_last_modified_stamp,) = struct.unpack('<I', buf[1:1+4])
            else:
                print(f"ignore extended header 0x{ext_type:02x}")

            crc = self.crcio.calccrc(crc, buf, len(buf))

            if self.size_field_length == 2:
                (header_size,) = struct.unpack('<H', buf[-2:])
                whole_size += header_size
            else:
                (header_size,) = struct.unpack('<I', buf[-4:])
                whole_size += header_size

        if dir_length:
            self.name = dirname + self.name

        return (whole_size, crc)

##############################################################################

class Huf:
    """New static Huffman decoder (from huf.c)"""
    MAXMATCH = 256
    THRESHOLD = 3
    USHRT_BIT = 16
    NT = USHRT_BIT + 3
    NC = 0xff + MAXMATCH + 2 - THRESHOLD
    NPT= 0x80

    TBIT = 5
    CBIT = 9

    BUFBITS = 16 # >= log2(MAXBUF), defined in lha_macro.h
    EXTRABITS = 8 # >= log2(F-THRESHOLD+258-N1), defined in lha_macro.h
    LENFIELD = 4 # bit size of length field for tree output, defined in lha_macro.h
    N1 = 286 # alphabet size in lha_macro.h
    NP = (8 * 1024 // 64) # defined in shuf.c
    fixed = [
        [3, 0x01, 0x04, 0x0C, 0x18, 0x30, 0] + [0] * (16 - 7),  # old compatible
        [2, 0x01, 0x01, 0x03, 0x06, 0x0D, 0x1F, 0x4E, 0] + [0] * (16 - 9)  # 8K buf
    ] # defined in shuf.c

    N_CHAR = 256 + 60 - THRESHOLD + 1 # defined in lha_macro.h
    TREESIZE_C = N_CHAR * 2 # defined in lha_macro.h
    TREESIZE_P = 128 * 2 # defined in lha_macro.h
    TREESIZE = TREESIZE_C + TREESIZE_P # defined in lha_macro.h
    ROOT_C = 0 # defined in lha_macro.h
    ROOT_P = TREESIZE_C # defined in lha_macro.h

    def __init__(self, interface):

        """Decoders (from slide.c)"""
        self.decoders = {
            b'-lh1-': (self.decode_c_dyn, self.decode_p_st0, self.decode_start_fix),
            b'-lh2-': (self.decode_c_dyn, self.decode_p_dyn, self.decode_start_dyn),
            b'-lh3-': (self.decode_c_st0, self.decode_p_st0, self.decode_start_st0),
            b'-lh4-': (self.decode_c_st1, self.decode_p_st1, self.decode_start_st1),
            b'-lh5-': (self.decode_c_st1, self.decode_p_st1, self.decode_start_st1),
            b'-lh6-': (self.decode_c_st1, self.decode_p_st1, self.decode_start_st1),
            b'-lh7-': (self.decode_c_st1, self.decode_p_st1, self.decode_start_st1),
        }

        if interface.header.method not in self.decoders:
            raise RuntimeError("unknown decoder")

        self.interface = interface
        self.pbit = interface.pbit
        self.np = interface.np
        self.b = BitIo(self.interface.fh, self.interface.packed)
        self.blocksize = 0

        self.left = [0] * (2 * self.NC - 1)
        self.right = [0] * (2 * self.NC - 1)

        self.c_table = [0] * 4096
        self.pt_table = [0] * 256
        self.c_len = [0] * self.NC
        self.pt_len = [0] * self.NPT
        self.pt_code = [0] * self.NPT

        self.child = [0] * self.TREESIZE
        self.parent = [0] * self.TREESIZE
        self.block = [0] * self.TREESIZE
        self.edge = [0] * self.TREESIZE
        self.stock = [0] * self.TREESIZE
        self.s_node = [0] * (self.TREESIZE // 2)
        self.freq = [0] * self.TREESIZE

        (self.decode_c, self.decode_p, self.decode_start) = self.decoders[interface.header.method]

    def make_table(self, nchar, bitlen, tablebits, table):
        """Make decoding table (from maketbl.c)"""
        count = [0] * 17
        weight = [0] * 17
        start = [0] * 17

        avail = nchar

        # initialize
        for i in range(1, 17):
            count[i] = 0
            weight[i] = 1 << (16 - i)

        # count
        for i in range(nchar):
            if bitlen[i] > 16:
                raise RuntimeError("Bad table (case a)")
            count[bitlen[i]] += 1

        # calculate first code
        total = 0
        for i in range(1, 17):
            start[i] = total
            total = (total + weight[i] * count[i]) & 0xffff
        if ((total & 0xffff) != 0) or (tablebits > 16):
            raise RuntimeError("Bad table (case b)")

        # shift data for make table.
        m = 16 - tablebits
        for i in range(1, tablebits + 1):
            start[i] >>= m
            weight[i] >>= m

        # initialize
        j = start[tablebits + 1] >> m
        k = min(1 << tablebits, 4096)
        if j != 0:
            for i in range(j, k):
                table[i] = 0

        # create table and tree
        for j in range(nchar):
            k = bitlen[j]
            if k == 0:
                continue
            l = start[k] + weight[k]
            if k <= tablebits:
                # code in table
                l = min(l, 4096)
                for i in range(start[k], l):
                    table[i] = j
            else:
                # code not in table:
                i = start[k]
                if (i >> m) > 4096:
                    raise RuntimeError("Bad table (case c)")
                pt = table
                pi = i >> m
                i <<= tablebits
                n = k - tablebits
                # make tree (n length)
                while True:
                    n -= 1
                    if not (n >= 0):
                        break
                    if pt[pi] == 0:
                        self.right[avail] = 0
                        self.left[avail] = 0
                        pt[pi] = avail
                        avail += 1
                    if i & 0x8000:
                        pi = pt[pi]
                        pt = self.right
                    else:
                        pi = pt[pi]
                        pt = self.left
                    i <<= 1
                pt[pi] = j
            start[k] = l

    def read_pt_len(self, nn, nbit, i_special):
        n = self.b.getbits(nbit)
        if n == 0:
            c = self.b.getbits(nbit)
            for i in range(nn):
                self.pt_len[i] = 0
            for i in range(256):
                self.pt_table[i] = c
        else:
            i = 0
            while i < min(n, self.NPT):
                c = self.b.peekbits(3)
                if c != 7:
                    self.b.fillbuf(3)
                else:
                    mask = 1 << (16 - 4)
                    while mask & self.b.bitbuf:
                        mask >>= 1
                        c += 1
                    self.b.fillbuf(c - 3)

                self.pt_len[i] = c
                i += 1
                if i == i_special:
                    c = self.b.getbits(2)
                    while True:
                        c -= 1
                        if not (c >= 0 and i < self.NPT):
                            break
                        self.pt_len[i] = 0
                        i += 1
            while i < nn:
                self.pt_len[i] = 0
                i += 1
            self.make_table(nn, self.pt_len, 8, self.pt_table)

    def read_c_len(self):
        n = self.b.getbits(self.CBIT)
        if n == 0:
            c = self.b.getbits(self.CBIT)
            for i in range(self.NC):
                self.c_len[i] = 0
            for i in range(4096):
                self.c_table[i] = c
        else:
            i = 0
            while i < min(n, self.NC):
                c = self.pt_table[self.b.peekbits(8)]
                if c >= self.NT:
                    mask = 1 << (16 - 9)
                    while True:
                        if self.b.bitbuf & mask:
                            c = self.right[c]
                        else:
                            c = self.left[c]
                        mask >>= 1
                        if not (c >= self.NT and (mask or c != self.left[c])):
                            break
                self.b.fillbuf(self.pt_len[c])
                if c <= 2:
                    if c== 0:
                        c = 1
                    elif c == 1:
                        c = self.b.getbits(4) + 3
                    else:
                        c = self.b.getbits(self.CBIT) + 20
                    while True:
                        c -= 1
                        if not (c >= 0):
                            break
                        self.c_len[i] = 0
                        i += 1
                else:
                    self.c_len[i] = c - 2;
                    i += 1
            while i < self.NC:
                self.c_len[i] = 0
                i += 1
            self.make_table(self.NC, self.c_len, 12, self.c_table)

    def decode_c_st1(self):
        if self.blocksize == 0:
            self.blocksize = self.b.getbits(16)
            self.read_pt_len(self.NT, self.TBIT, 3)
            self.read_c_len()
            self.read_pt_len(self.np, self.pbit, -1)
        self.blocksize -= 1
        j = self.c_table[self.b.peekbits(12)]
        if j < self.NC:
            self.b.fillbuf(self.c_len[j])
        else:
            self.b.fillbuf(12)
            mask = 1 << (16 - 1)
            while True:
                if self.b.bitbuf & mask:
                    j = self.right[j]
                else:
                    j = self.left[j]
                mask >>= 1
                if not (j >= self.NC and (mask or j != self.left[j])):
                    break
            self.b.fillbuf(self.c_len[j] - 12)
        return j

    def decode_p_st1(self, decode_count):
        j = self.pt_table[self.b.peekbits(8)]
        if j < self.np:
            self.b.fillbuf(self.pt_len[j])
        else:
            self.b.fillbuf(8)
            mask = 1 << (16 - 1)
            while True:
                if self.b.bitbuf & mask:
                    j = self.right[j]
                else:
                    j = self.left[j]
                mask >>= 1
                if not (j >= self.np and (mask or j != self.left[j])):
                    break
            self.b.fillbuf(self.pt_len[j] - 8)
        if j != 0:
            j = (1 << (j - 1)) + self.b.getbits(j - 1)
        return j

    def decode_start_st1(self):
        pass

    def read_tree_c(self):
        i = 0
        while i < self.N1:
            if self.b.getbits(1):
                self.c_len[i] = self.b.getbits(self.LENFIELD) + 1
            else:
                self.c_len[i] = 0
            i += 1
            if i == 3 and self.c_len[0] == 1 and self.c_len[1] == 1 and self.c_len[2] == 1:
                c = self.b.getbits(CBIT)
                for j in range(0, self.N1):
                    self.c_len[j] = 0
                for j in range(0, 4096):
                    self.c_table[j] = c
                return
        self.make_table(self.N1, self.c_len, 12, self.c_table)

    def read_tree_p(self):
        i = 0
        while i < self.NP:
            self.pt_len[i] = self.b.getbits(self.LENFIELD)
            i += 1
            if i == 3 and pt_len[0] == 1 and pt_len[1] == 1 and pt_len[2] == 1:
                c = self.b.getbits(self.interface.dicbit - 6)
                for j in range(0, self.NP):
                    self.pt_len[j] = 0
                for j in range(0, 256):
                    self.pt_table[j] = c
                return

    def ready_made(self, method):
        idx = 0
        tbl = self.fixed[method]
        j = tbl[idx]
        idx += 1
        weight = 1 << (16 - j)
        code = 0
        for i in range(0, self.np):
            while tbl[idx] == i:
                j += 1
                idx += 1
                weight >>= 1
            self.pt_len[i] = j
            self.pt_code[i] = code
            code += weight

    def decode_c_st0(self):
        if self.blocksize == 0: # read block head
            self.blocksize = self.b.getbits(self.BUFBITS) # read block blocksize
            self.read_tree_c()
            if self.b.getbits(1):
                self.read_tree_p()
            else:
                self.ready_made(1)
            self.make_table(self.NP, self.pt_len, 8, self.pt_table)
        self.blocksize -= 1
        j = self.c_table[self.b.peekbits(12)]
        if j < self.N1:
            self.b.fillbuf(c_len[j])
        else:
            self.b.fillbuf(12)
            mask = 1 << (16 - 1)
            while True:
                if self.b.bitbuf & mask:
                    j = self.right[j]
                else:
                    j = self.left[j]
                mask >>= 1
                if j < self.N1:
                    break
            self.b.fillbuf(c_len[j] - 12)
        if j == self.N1 - 1:
            j += self.b.getbits(self.EXTRABITS)
        return j

    def decode_p_st0(self, decode_count):
        j = self.pt_table[self.b.peekbits(8)]
        if j < self.np:
            self.b.fillbuf(self.pt_len[j])
        else:
            self.b.fillbuf(8)
            mask = 1 << (16 - 1)
            while True:
                if self.b.bitbuf & mask:
                    j = self.right[j]
                else:
                    j = self.left[j]
                mask >>= 1
                if j < self.np:
                    break
            self.b.fillbuf(self.pt_len[j] - 8)
        return (j << 6) + self.b.getbits(6)

    def decode_start_st0(self):
        self.np = 1 << (self.interface.dicbit - 6)

    def start_c_dyn(self):
        self.n1 = 512 if (self.n_max >= 256 + self.maxmatch - self.THRESHOLD + 1) else (self.n_max - 1)
        for i in range(0, self.TREESIZE_C):
            self.stock[i] = i
            self.block[i] = 0
        j = self.n_max * 2 - 2
        for i in range(0, self.n_max):
            self.freq[j] = 1
            self.child[j] = ~i
            self.s_node[i] = j
            self.block[j] = 1
            j -= 1
        self.avail = 2
        self.edge[1] = self.n_max - 1
        i = self.n_max * 2 - 2
        while j >= 0:
            f = self.freq[j] = self.freq[i] + self.freq[i - 1]
            self.child[j] = i
            self.parent[i] = self.parent[i - 1] = j
            if f == self.freq[j + 1]:
                self.block[j] = self.block[j + 1]
                self.edge[self.block[j]] = j
            else:
                self.block[j] = self.stock[self.avail]
                self.avail += 1
                self.edge[self.block[j]] = j
            i -= 2
            j -= 1

    def start_p_dyn(self):
        self.freq[self.ROOT_P] = 1
        self.child[self.ROOT_P] = ~(self.N_CHAR)
        self.s_node[self.N_CHAR] = self.ROOT_P
        self.block[self.ROOT_P] = stock[self.avail]
        self.avail += 1
        self.edge[self.block[self.ROOT_P]] = self.ROOT_P
        self.most_p = self.ROOT_P
        self.total_p = 0
        self.nn = 1 << self.dicbit
        self.nextcount = 64

    def decode_start_dyn(self):
        self.n_max = 286
        maxmatch = MAXMATCH
        start_c_dyn()
        start_p_dyn()

    def reconst(self, start, end):
        j = start
        for i in range(start, end):
            if (k := self.child[i]) < 0:
                self.freq[j] = (self.freq[i] + 1) // 2
                self.child[j] = k
                j += 1
            b = self.block[i]
            if self.edge[b] == i:
                self.avail -= 1
                self.stock[self.avail] = b
        j -= 1
        i = end - 1
        l = end - 2
        while i >= start:
            while i >= l:
                self.freq[i] = self.freq[j]
                self.child[i] = self.child[j]
                i -= 1
                j -= 1
            f = self.freq[l] + self.freq[l + 1]
            k = start
            while f < self.freq[k]:
                k += 1
            while j >= k:
                self.freq[i] = self.freq[j]
                self.child[i] = self.child[j]
                i -= 1
                j -= 1
            self.freq[i] = f
            self.child[i] = l + 1
            i -= 1
            l -= 2
        f = 0
        for i in range(start, end):
            if (j := self.child[i]) < 0:
                self.s_node[~j] = i
            else:
                self.parent[j] = self.parent[j - 1] = i
            if (g := self.freq[i]) == f:
                self.block[i] = b
            else:
                b = self.block[i] = self.stock[self.avail]
                self.avail += 1
                self.edge[b] = i
                f = g

    def swap_inc(self, p):
        b = self.block[p]
        if (q := self.edge[b]) != p: # swap for leader
            r = self.child[p]
            s = self.child[q]
            self.child[p] = s
            self.child[q] = r
            if r >= 0:
                self.parent[r] = self.parent[r - 1] = q
            else:
                self.s_node[~r] = q
            if s >= 0:
                self.parent[s] = self.parent[s - 1] = p
            else:
                self.s_node[~s] = p
            p = q
            self.edge[b] += 1
            self.freq[p] += 1
            if self.freq[p] == self.freq[p - 1]:
                self.block[p] = self.block[p - 1]
            else:
                self.block[p] = self.stock[self.avail]
                self.avail += 1
                self.edge[self.block[p]] = p # create block
        elif b == self.block[p + 1]:
            self.edge[b] += 1
            self.freq[p] += 1
            if self.freq[p] == self.freq[p - 1]:
                self.block[p] = self.block[p - 1]
            else:
                self.block[p] = self.stock[self.avail]
                self.avail += 1
                self.edge[self.block[p]] = p # create block
        else:
            self.freq[p] += 1
            if self.freq[p] == self.freq[p - 1]:
                self.avail -= 1
                self.stock[self.avail] = b # delete block
                self.block[p] = self.block[p - 1]
        return self.parent[p]

    def update_c(self, p):
        if self.freq[self.ROOT_C] == 0x8000:
            self.reconst(0, self.n_max * 2 - 1)
        self.freq[self.ROOT_C] += 1
        q = self.s_node[p]
        while True:
            q = self.swap_inc(q)
            if q == self.ROOT_C:
                break

    def update_p(self, p):
        if self.total_p == 0x8000:
            self.reconst(self.ROOT_P, self.most_p + 1)
            self.total_p = self.freq[self.ROOT_P]
            self.freq[ROOT_P] = 0xffff
        q = self.s_node[p + self.N_CHAR]
        while q != ROOT_P:
            q = self.swap_inc(q)
        self.total_p += 1

    def make_new_node(self, p):
        r = self.most_p + 1
        q = r + 1
        self.child[r] = self.child[self.most_p]
        self.s_node[~(self.child[r])] = r
        self.child[q] = ~(p + self.N_CHAR)
        self.child[self.most_p] = q
        self.freq[r] = self.freq[self.most_p]
        self.freq[q] = 0
        self.block[r] = self.block[self.most_p]
        if self.most_p == self.ROOT_P:
            self.freq[self.ROOT_P] = 0xffff
            self.edge[self.block[self.ROOT_P]] += 1
        self.parent[r] = self.parent[q] = self.most_p
        self.block[q] = stock[self.avail]
        self.avail += 1
        self.edge[self.block[q]] = self.s_node[p + self.N_CHAR] = self.most_p = q
        self.update_p(p)

    def decode_c_dyn(self):
        c = self.child[self.ROOT_C]
        buf = self.b.bitbuf
        cnt = 0
        while True:
            mask = 1 << (16 - 1)
            offset = 1 if mask & buf else 0
            c = self.child[c - offset]
            buf <<= 1
            cnt += 1
            if cnt == 16:
                self.b.fillbuf(16)
                buf = self.b.bitbuf
                cnt = 0
            if c <= 0:
                break
        self.b.fillbuf(cnt)
        c = ~c
        self.update_c(c)
        if c == self.n1:
            c += self.b.getbits(8)
        return c

    def decode_p_dyn(self, decode_count):
        while decode_count > self.nextcount:
            self.make_new_node(self.nextcount // 64)
            self.nextcount += 64
            if self.nextcount >= nn:
                self.nextcount = 0xffffffff
        c = self.child[self.ROOT_P]
        buf = self.b.bitbuf
        cnt = 0
        while c > 0:
            mask = 1 << (16 - 1)
            offset = 1 if mask & buf else 0
            c = self.child[c - offset]
            buf <<= 1
            cnt += 1
            if cnt == 16:
                self.b.fillbuf(16)
                buf = self.b.bitbuf
                cnt = 0
        self.b.fillbuf(cnt)
        c = (~c) - self.N_CHAR
        self.update_p(c)
        return (c << 6) + self.b.getbits(6)

    def decode_start_fix(self):
        self.n_max = 314
        self.maxmatch = 60
        self.np = 1 << (self.interface.dicbit - 6)
        self.start_c_dyn()
        self.ready_made(0)
        self.make_table(self.np, self.pt_len, 8, self.pt_table)

##############################################################################

class Interface:
    """Decoder interface (extract.c:decode_lzhuf())"""
    methods = {
        b'-lh0-': (False,  0, 0,  0),          # None
        b'-lh1-': (False, 12, 0,  0),          # dyn,st0,fix
        b'-lh2-': (False, 13, 0,  0),          # dyn,dyn,syn
        b'-lh3-': (False, 13, 0,  0),          # st0,st0,st0
        b'-lh4-': (False, 12, 4, 14),          # st1,st1,st1
        b'-lh5-': (False, 13, 4, 14),          # st1,st1,st1
        b'-lh6-': (False, 15, 5, 16),          # st1,st1,st1
        b'-lh7-': (False, 16, 5, 17),          # st1,st1,st1
        b'-lhd-': (True,   0, 0,  0),          # None
    }

    def __init__(self, fh, header):
        if header.method not in self.methods:
            raise RuntimeError("unknown method")

        self.fh = fh
        self.fo = None
        self.header = header
        self.crcio = header.crcio

        self.original = self.header.original_size
        self.packed = self.header.packed_size
        self.read_size = 0

        self.isdir = self.methods[header.method][0]
        self.dicbit = self.methods[header.method][1]
        self.pbit = self.methods[header.method][2]
        self.np = self.methods[header.method][3]

##############################################################################

def decode(interface):
    """Decode bit stream (from slide.c)"""
    if interface.dicbit == 0:
        pass

    crc = 0
    dicsiz = 1 << interface.dicbit
    dtext = bytearray(dicsiz)

    huf = Huf(interface)
    dicsiz1 = dicsiz - 1
    adjust = 256 - huf.THRESHOLD

    huf.decode_start()
    decode_count = 0
    loc = 0
    while decode_count < interface.header.original_size:
        c = huf.decode_c()
        if c < 256:
            dtext[loc] = c
            loc += 1
            if loc == dicsiz:
                crc = interface.crcio.calccrc(crc, dtext, len(dtext))
                interface.fo.write(dtext)
                loc = 0
            decode_count += 1
        else:
            class MatchData:
                pass
            match =  MatchData
            match.len = c - adjust
            match.off = huf.decode_p(decode_count) + 1
            matchpos = (loc - match.off) & dicsiz1
            decode_count += match.len
            for i in range(match.len):
                c = dtext[(matchpos + i) & dicsiz1]
                dtext[loc] = c
                loc += 1
                if loc == dicsiz:
                    crc = interface.crcio.calccrc(crc, dtext, len(dtext))
                    interface.fo.write(dtext)
                    loc = 0
    if loc != 0:
        crc = interface.crcio.calccrc(crc, dtext, loc)
        interface.fo.write(dtext[0:loc])

    return crc


def decode_lzhuf(interface):
    """Decode LzHuf (from extract.c)"""
    if interface.dicbit == 0:
        buf = interface.fh.read(interface.original)
        crc = interface.crcio.calccrc(0, buf, len(buf))
        interface.fo.write(buf)
    else:
        crc = decode(interface)
    return crc


def extract_one(fh, header):
    """Extract one file (from lhext.c)"""
    interface = Interface(fh, header)

    if interface.isdir:
        os.makedirs(header.name, exist_ok=True)
        res = 0
    else:
        try:
            interface.fo = open(header.name, 'wb')
        except:
            os.makedirs(os.path.dirname(header.name), exist_ok=True)
            interface.fo = open(header.name, 'wb')
        crc = decode_lzhuf(interface)
        interface.fo.close()

        if interface.header.has_crc and crc != interface.header.crc:
            raise RuntimeError(f"CRC error: {header.name} computed: 0x{crc:04x} header: 0x{interface.header.crc:04x}")
        res = interface.packed

    try:
        os.utime(header.name, (interface.header.unix_last_modified_stamp, interface.header.unix_last_modified_stamp))
    except:
        pass

    return res


UNLHA_LIST = 0
UNLHA_EXTRACT = 1

def unlha(fh, mode, extfiles):
    """Extract command main (from lhext.c:cmd_extract())"""
    header = LzhHeader()
    while header.get_header(fh):
        found = not extfiles
        if not found:
            for f in extfiles:
                fd = f + '/' if not f[-1] == '/' else f
                if (header.name == f) or (header.name == f + '/') or header.name.startswith(fd):
                    found = True
                    break

        if not found:
            fh.seek(header.packed_size, os.SEEK_CUR)
            continue

        if mode == UNLHA_EXTRACT:
            pos = fh.tell()
            print(header.name)
            extract_one(fh, header)
            fh.seek(pos + header.packed_size, os.SEEK_SET)
        else:
            print(f'{header.original_size:8d}  {time.asctime(time.localtime(header.unix_last_modified_stamp))}  {header.name}')
            fh.seek(header.packed_size, os.SEEK_CUR)


def usage():
    print('Simple LZH archive extractor -- unlha.py')
    print('Python version copyright (c) 2024 Yuichi Nakamura (@yunkya2)')
    print(' URL: https://github.com/yunkay2/unlha')
    print(' LICENSE condition: https://github.com/yunkya2/unlha/blob/main/LICENSE')
    print('----------------------------------------------------------------')
    print('This software is derived from "LHa for UNIX with Autoconf"')
    print('LHarc    for UNIX  V 1.02  Copyright(C) 1989  Y.Tagawa')
    print('LHx      for MSDOS V C2.01 Copyright(C) 1990  H.Yoshizaki')
    print('LHx(arc) for OSK   V 2.01  Modified     1990  Momozou')
    print('LHa      for UNIX  V 1.00  Copyright(C) 1992  Masaru Oki')
    print('LHa      for UNIX  V 1.14  Modified     1995  Nobutaka Watazaki')
    print('LHa      for UNIX  V 1.14i Modified     2000  Tsugio Okamoto')
    print('LHA-PMA  for UNIX  V 2     PMA added    2000  Maarten ter Huurne')
    print('                   Autoconfiscated 2001-2008  Koji Arai')
    print('')
    print('usage: unlha.py [<commands>] archive_file [file...]')
    print('commands:')
    print(' x,e  Extract from archive')
    print(' t,l  List archive contents')
    sys.exit(1)

##############################################################################

if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()

    mode = -1
    p = 2
    if sys.argv[1] == 't' or sys.argv[1] == 'l':
        mode = UNLHA_LIST
    elif sys.argv[1] == 'e' or sys.argv[1] == 'x':
        mode = UNLHA_EXTRACT

    if mode < 0:
        mode = UNLHA_LIST
        p = 1

    if len(sys.argv) <= p:
        usage()

    infile = sys.argv[p]
    extfiles = sys.argv[p + 1:]

    try:
        with open(infile, "rb") as fh:
            unlha(fh, mode, extfiles)
    except (FileNotFoundError, IsADirectoryError, NotADirectoryError, FileExistsError, PermissionError, RuntimeError) as e:
        print(sys.argv[0] + ': error: ' + str(e))
        sys.exit(1)

    sys.exit(0)
