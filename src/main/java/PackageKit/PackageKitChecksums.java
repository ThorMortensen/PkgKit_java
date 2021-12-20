package PackageKit;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.bytes.BytesTransformer;
import org.apache.commons.lang3.NotImplementedException;
import org.apache.poi.util.NotImplemented;

public abstract class PackageKitChecksums implements BytesTransformer {

    /**
     * Return size in bytes of the checksum/CRC digest.
     *
     * @return
     */
    public abstract int digestByteSize();

    public abstract boolean check(Bytes bytes);

    public abstract String description();

    @Override
    public final boolean supportInPlaceTransformation() {
        return false;
    }

    public static PackageKitChecksums crc16_std_PUS_ECSS_E_ST_70_41C_2016() {
        return new Crc16_std_PUS_ECSS_E_ST_70_41C_2016();
    }

    @NotImplemented
    public static PackageKitChecksums crc16_iso_PUS_ECSS_E_ST_70_41C_2016() {
        throw new NotImplementedException("ISO version is TBD. Use std version!");
    }

    public static PackageKitChecksums crc8_RMAP_ECSS_E_ST_50_52C_2010() {
        return new Crc8_RMAP_ECSS_E_ST_50_52C_2010();
    }

    private static final class Crc16_std_PUS_ECSS_E_ST_70_41C_2016 extends PackageKitChecksums {

        private final int[] lut;
        private static final int DEFAULT_CRC_SYNDROME = 0xFFFF;

        public Crc16_std_PUS_ECSS_E_ST_70_41C_2016() {
            lut = new int[256];
            {
                int tmp;
                for (int i = 0; i < 256; i++) {
                    tmp = 0;
                    if ((i & 1) != 0) tmp = tmp ^ 0x1021;
                    if ((i & 2) != 0) tmp = tmp ^ 0x2042;
                    if ((i & 4) != 0) tmp = tmp ^ 0x4084;
                    if ((i & 8) != 0) tmp = tmp ^ 0x8108;
                    if ((i & 16) != 0) tmp = tmp ^ 0x1231;
                    if ((i & 32) != 0) tmp = tmp ^ 0x2462;
                    if ((i & 64) != 0) tmp = tmp ^ 0x48C4;
                    if ((i & 128) != 0) tmp = tmp ^ 0x9188;
                    lut[i] = tmp;
                }
            }
        }

        @Override
        public int digestByteSize() {
            return 2;
        }

        @Override
        public boolean check(Bytes bytes) {
            int check = DEFAULT_CRC_SYNDROME;
            for (byte b : bytes) {
                check = crcCalc(b, check);
            }

            return check == 0;
        }

        @Override
        public String description() {
            return "PUS CRC16";
        }

        @Override
        public byte[] transform(byte[] currentArray, boolean inPlace) {
            int syndrome = DEFAULT_CRC_SYNDROME;
            for (byte b : currentArray) {
                syndrome = crcCalc(b, syndrome);
            }
            return Bytes.from(syndrome).resize(2).array();
        }

        private int crcCalc(byte byteToEncode, int syndrome) {
            return (((syndrome << 8) & 0xFF00) ^ lut[(((syndrome >> 8) ^ byteToEncode) & 0x00FF)]);
        }
    }


    /**
     -----------------------------------------------------------------------------
     -- Cyclic Redundancy Code (CRC) for Remote Memory Access Protocol (RMAP)
     -----------------------------------------------------------------------------
     -- Purpose:
     -- Given an intermediate SpaceWire RMAP CRC byte value and an RMAP Header
     -- or Data byte, return an updated RMAP CRC byte value.
     --
     -- Parameters:
     -- INCRC - The RMAP Header or Data byte.
     -- INBYTE - The intermediate RMAP CRC byte value.
     --
     -- Return value:
     -- OUTCRC - The updated RMAP CRC byte value.
     --
     -- Description:
     -- Table look-up version: uses the XOR of the intermediate CRC byte with the
     -- header/data byte to obtain the updated CRC byte from a look-up table.
     --
     --  Generator polynomial: g(x) = x**8 + x**2 + x**1 + x**0
     --
     -- Notes:
     -- The INCRC input CRC value must have all bits zero for the first INBYTE.
     --
     -- The first INBYTE must be the first Header or Data byte covered by the
     -- RMAP CRC calculation. The remaining bytes must be supplied in the RMAP
     -- transmission/reception byte order.
     --
     -- If the last INBYTE is the last Header or Data byte covered by the RMAP
     -- CRC calculation then the OUTCRC output will be the RMAP CRC byte to be
     -- used for transmission or to be checked against the received CRC byte.
     --
     -- If the last INBYTE is the Header or Data CRC byte then the OUTCRC
     -- output will be zero if no errors have been detected and non-zero if
     -- an error has been detected.
     --
     -- Each byte is inserted in or extracted from a SpaceWire packet without
     -- the need for any bit reversal or similar manipulation. The SpaceWire
     -- packet transmission and reception procedure does the necessary bit
     -- ordering when sending and receiving Data Characters (see ECSS-E-ST-50-12).
     -----------------------------------------------------------------------------
     */
    private static final class Crc8_RMAP_ECSS_E_ST_50_52C_2010 extends PackageKitChecksums {

        private static final int[] lut = {
                0x00, 0x91, 0xe3, 0x72, 0x07, 0x96, 0xe4, 0x75,
                0x0e, 0x9f, 0xed, 0x7c, 0x09, 0x98, 0xea, 0x7b,
                0x1c, 0x8d, 0xff, 0x6e, 0x1b, 0x8a, 0xf8, 0x69,
                0x12, 0x83, 0xf1, 0x60, 0x15, 0x84, 0xf6, 0x67,
                0x38, 0xa9, 0xdb, 0x4a, 0x3f, 0xae, 0xdc, 0x4d,
                0x36, 0xa7, 0xd5, 0x44, 0x31, 0xa0, 0xd2, 0x43,
                0x24, 0xb5, 0xc7, 0x56, 0x23, 0xb2, 0xc0, 0x51,
                0x2a, 0xbb, 0xc9, 0x58, 0x2d, 0xbc, 0xce, 0x5f,
                0x70, 0xe1, 0x93, 0x02, 0x77, 0xe6, 0x94, 0x05,
                0x7e, 0xef, 0x9d, 0x0c, 0x79, 0xe8, 0x9a, 0x0b,
                0x6c, 0xfd, 0x8f, 0x1e, 0x6b, 0xfa, 0x88, 0x19,
                0x62, 0xf3, 0x81, 0x10, 0x65, 0xf4, 0x86, 0x17,
                0x48, 0xd9, 0xab, 0x3a, 0x4f, 0xde, 0xac, 0x3d,
                0x46, 0xd7, 0xa5, 0x34, 0x41, 0xd0, 0xa2, 0x33,
                0x54, 0xc5, 0xb7, 0x26, 0x53, 0xc2, 0xb0, 0x21,
                0x5a, 0xcb, 0xb9, 0x28, 0x5d, 0xcc, 0xbe, 0x2f,
                0xe0, 0x71, 0x03, 0x92, 0xe7, 0x76, 0x04, 0x95,
                0xee, 0x7f, 0x0d, 0x9c, 0xe9, 0x78, 0x0a, 0x9b,
                0xfc, 0x6d, 0x1f, 0x8e, 0xfb, 0x6a, 0x18, 0x89,
                0xf2, 0x63, 0x11, 0x80, 0xf5, 0x64, 0x16, 0x87,
                0xd8, 0x49, 0x3b, 0xaa, 0xdf, 0x4e, 0x3c, 0xad,
                0xd6, 0x47, 0x35, 0xa4, 0xd1, 0x40, 0x32, 0xa3,
                0xc4, 0x55, 0x27, 0xb6, 0xc3, 0x52, 0x20, 0xb1,
                0xca, 0x5b, 0x29, 0xb8, 0xcd, 0x5c, 0x2e, 0xbf,
                0x90, 0x01, 0x73, 0xe2, 0x97, 0x06, 0x74, 0xe5,
                0x9e, 0x0f, 0x7d, 0xec, 0x99, 0x08, 0x7a, 0xeb,
                0x8c, 0x1d, 0x6f, 0xfe, 0x8b, 0x1a, 0x68, 0xf9,
                0x82, 0x13, 0x61, 0xf0, 0x85, 0x14, 0x66, 0xf7,
                0xa8, 0x39, 0x4b, 0xda, 0xaf, 0x3e, 0x4c, 0xdd,
                0xa6, 0x37, 0x45, 0xd4, 0xa1, 0x30, 0x42, 0xd3,
                0xb4, 0x25, 0x57, 0xc6, 0xb3, 0x22, 0x50, 0xc1,
                0xba, 0x2b, 0x59, 0xc8, 0xbd, 0x2c, 0x5e, 0xcf
        };
        private static final int DEFAULT_CRC_SYNDROME = 0;

        public Crc8_RMAP_ECSS_E_ST_50_52C_2010() {
        }

        @Override
        public int digestByteSize() {
            return 1;
        }

        @Override
        public boolean check(Bytes bytes) {

            int check = DEFAULT_CRC_SYNDROME;
            for (byte b : bytes) {
                check = crcCalc(b, check);
            }

            return check == 0;
        }

        @Override
        public String description() {
            return "RMAP CRC8";
        }

        @Override
        public byte[] transform(byte[] currentArray, boolean inPlace) {
            int syndrome = DEFAULT_CRC_SYNDROME;
            for (byte b : currentArray) {
                syndrome = crcCalc(b, syndrome);
            }
            return Bytes.from(syndrome).resize(digestByteSize()).array();
        }

        private int crcCalc(byte inByte, int inCrc) {
            return lut[inCrc ^ inByte];
        }
    }


}
