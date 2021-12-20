package PackageKit;

import at.favre.lib.bytes.Bytes;
import lombok.Getter;

import java.util.HashMap;

import static at.favre.lib.bytes.BytesTransformer.ResizeTransformer.Mode.RESIZE_KEEP_FROM_ZERO_INDEX;

public class PackageKit {
    private final HashMap<String, Field> headerComposition;
    private final HashMap<String, PackageKit> headerSubFieldMap;
    private final boolean useSeparateChecksum;
    private Field head;
    private Field tail;
    private int headerBitSum = 0;

    @Getter
    private final String pkgName;
    private Bytes payload;
    private Bytes dismantledPkg;
    private final int pecSizeHeader;
    private final int pecSizePayload;

    private int ppPad = 0;
    private final PackageKitChecksums checksum;

    public PackageKit(String pkgName, PackageKitChecksums checksum, boolean useSeparateHeaderChecksum) {
        this.pkgName = pkgName;
        headerComposition = new HashMap<>();
        headerSubFieldMap = new HashMap<>();
        payload = Bytes.empty();
        dismantledPkg = Bytes.empty();
        this.checksum = checksum;
        this.useSeparateChecksum = useSeparateHeaderChecksum;
        if (checksum == null) {
            pecSizeHeader = 0;
            pecSizePayload = 0;
        } else {
            pecSizePayload = checksum.digestByteSize();
            pecSizeHeader = useSeparateHeaderChecksum ? pecSizePayload : 0;
        }
    }

    public PackageKit(String pkgName, PackageKitChecksums checksum) {
        this(pkgName, checksum, false);
    }

    public PackageKit(String pkgName) {
        this(pkgName, null, false);
    }

    public PackageKit(PackageKit fromPkg, String cloneName) {
        this(cloneName, fromPkg.checksum, fromPkg.useSeparateChecksum);
        cloneFields(fromPkg.head);
    }

    public PackageKit(PackageKit fromPkg) {
        this(fromPkg, fromPkg.pkgName);
    }

    /***************************
     *       Fields
     **************************/
    public PackageKit addField(String fieldName, int bitLength, int fieldValue) {
        ppPad = Integer.max(fieldName.length(), ppPad);
        headerBitSum += bitLength;
        if (head == null) {
            head = new Field(fieldName, bitLength, fieldValue);
            tail = head;
        } else {
            tail.nextField = new Field(fieldName, bitLength, fieldValue);
            tail = tail.nextField;
        }
        headerComposition.put(fieldName, tail);
        return this;
    }

    public PackageKit addField(String fieldName, int bitLength) {
        addField(fieldName, bitLength, 0);
        return this;
    }

    public PackageKit addFieldsFrom(PackageKit from) {
        PackageKit sub = new PackageKit(from);
        headerSubFieldMap.put(sub.pkgName, sub);
        ppPad = Integer.max(sub.ppPad, ppPad);
        tail.nextField = sub.head;
        tail = sub.tail;
        headerComposition.putAll(sub.headerComposition);
        return this;
    }


    public Field getField(String name) {
        try {
            return headerComposition.get(name);
        } catch (NullPointerException e) {
            System.err.println("PackageKit " + pkgName + ": Field name '" + name + "' doesn't exist. Nothing to get!");
        }
        return new Field("null", 8, 0);
    }

    public PackageKit getSubPkg(String name) {
        try {
            return headerSubFieldMap.get(name);
        } catch (NullPointerException e) {
            System.err.println("PackageKit " + pkgName + ": Sub-Package name '" + name + "' doesn't exist. Nothing to get!");
        }
        return null;
    }

    public PackageKit setSubPkg(String name, Bytes value) {
        try {
            return headerSubFieldMap.get(name).fromBytes(value);
        } catch (NullPointerException e) {
            System.err.println("PackageKit " + pkgName + ": Sub-Package name '" + name + "' doesn't exist. Nothing to set!");
        }
        return null;
    }


    public Bytes getHeader() {
        return compileHeader();
    }

    /***************************
     *       Payload
     **************************/
    public PackageKit setPayload(Bytes data) {
        payload = data;
        return this;
    }

    public Bytes getPayload() {
        return payload;
    }

    /***************************
     *       Certify
     **************************/
    public Bytes getHeaderChecksum() {
        if (checksum == null) {
            return Bytes.empty();
        }
        return compileHeader().transform(checksum);
    }

    public Bytes getPayloadChecksum() {
        if (checksum == null || payload.isEmpty()) {
            return Bytes.empty();
        }
        return payload.transform(checksum);
    }

    public Bytes getChecksum() {
        if (checksum == null) {
            return Bytes.empty();
        }
        return compileHeader().append(payload).transform(checksum);
    }

    public boolean isHeaderChecksumOk() {
        if (checksum == null || dismantledPkg.isEmpty()) {
            return true;
        }

        return checksum.check(dismantledPkg.copy(0, headerSize()));
    }

    public boolean isPayloadChecksumOk() {
        if (checksum == null || payload.isEmpty()) {
            return true;
        }
        return checksum.check(payload);
    }

    public boolean isChecksumOk() {
        if (checksum == null || dismantledPkg.isEmpty()) {
            return true;
        }
        if (useSeparateChecksum) {
            return isHeaderChecksumOk() && isPayloadChecksumOk();
        }
        return checksum.check(dismantledPkg);
    }

    /***************************
     *         Access
     **************************/

    public void clear() {
        head.clearAll();
        payload = Bytes.empty();
        dismantledPkg = Bytes.empty();
    }

    public PackageKit fromBytes(byte[] bytes) {
        return fromBytes(Bytes.wrap(bytes));
    }

    public PackageKit fromBytes(Bytes pkgBytes) {
        assertHeaderSize();

        if (pkgBytes.length() < headerSize()) {
            System.err.println(pkgName + ": fromBytes input size is too small (" + pkgBytes.length() + ")! Input has been padded (" + (headerSize() - pkgBytes.length()) + ") to match header size (" + headerSize() + ")! (from LSB)");
            dismantledPkg = pkgBytes.resize(headerSize(), RESIZE_KEEP_FROM_ZERO_INDEX);
            head.dismantle(dismantledPkg);
            payload = Bytes.empty();
            return this;
        }

        head.dismantle(pkgBytes, 0);
        payload = pkgBytes.copy(headerSize() + pecSizeHeader, pkgBytes.length() - headerSize() - pecSizeHeader);
        dismantledPkg = pkgBytes;
        return this;
    }

    public Bytes toBytes() {
        assertHeaderSize();
        dismantledPkg = Bytes.empty();
        if (useSeparateChecksum) {
            return compileHeader().append(getHeaderChecksum()).append(payload).append(getPayloadChecksum());
        }
        return compileHeader().append(payload).append(getChecksum());
    }

    /***************************
     *         Info
     **************************/
    public int size() {
        return headerSize() + payloadSize();
    }

    public int headerSize() {
        return (headerBitSum / Byte.SIZE) + pecSizeHeader;
    }

    public int payloadSize() {
        return payload.length() + pecSizePayload;
    }


    private String formatChecksumString() {
        if (checksum == null) {
            return "";
        }
        String chk;
        if (useSeparateChecksum) {
            String headerRes = (dismantledPkg.isEmpty() ? getHeaderChecksum().encodeHex() : (isHeaderChecksumOk() ? "OK!" : "FAIL!"));
            String payloadRes = (dismantledPkg.isEmpty() ? getPayloadChecksum().encodeHex() : (payload.isEmpty() ? "" : (isPayloadChecksumOk() ? "OK!" : "FAIL!")));
            chk = String.format("Header  %s: %s\nPayload %s: %s", checksum.description(), headerRes, checksum.description(), payloadRes);
        } else {
            String pkgRes = (dismantledPkg.isEmpty() ? getChecksum().encodeHex() : (isChecksumOk() ? "OK!" : "FAIL!"));
            chk = String.format("%s: %s", checksum.description(), pkgRes);
        }
        return chk + '\n';
    }

    private String formatPkgString() {
        return (dismantledPkg.isEmpty() ? "Compiled Package : " + toBytes().encodeHex().toUpperCase() : "Dismantled Package :" + dismantledPkg.encodeHex().toUpperCase());
    }

    @Override
    public String toString() {


        return "=== PackageKit: '" + pkgName + '\'' + " ===\n" +
                "Size   : " + size() + " bytes" + '\n' +
                "--- Header composition ---" + '\n' +
                head.toStringNested(ppPad) + '\n' +
                "--- Pkg composition (hex) ---" + '\n' +
                "Header  : " + compileHeader().encodeHex().toUpperCase() + '\n' +
                "Payload : " + payload.encodeHex().toUpperCase() + '\n' +
                formatChecksumString() +
                formatPkgString() +
                '\n';

    }

    /***************************
     *        Internals
     **************************/
    private void assertHeaderSize() {
        if (headerBitSum % Byte.SIZE != 0) {
            throw new IllegalArgumentException("PackageKit invalid number of bits in header of " + pkgName + " (has " + headerBitSum + " bits). Must be multiple of Byte.SIZE");
        }
    }

    private Bytes compileHeader() {
        // If this is a subfield only compile this headerComposition(size).
        return head.compile(Bytes.allocate(headerSize()), this.headerComposition.size());
    }

    private void cloneFields(Field fromHead) {
        while (fromHead != null) {
            addField(fromHead.name, fromHead.bitSize, fromHead.fieldValue);
            fromHead = fromHead.nextField;
        }
    }


    public static class Field {
        private Field nextField;
        private final String name;
        private final int bitSize;
        private int fieldValue;
        private final int bit_mask;

        private Field(String name, int bitSize, int fieldValue) {
            if (bitSize > Integer.SIZE || bitSize < 1) {
                throw new IllegalArgumentException("PackageKit invalid field bitLength in " + name + ". Must be at least 1 an no more than Integer.SIZE");
            }
            this.bit_mask = 0xFFFFFFFF >>> Integer.SIZE - bitSize;
            this.name = name;
            this.bitSize = bitSize;
            this.fieldValue = fieldValue & bit_mask;
        }

        public void setValue(int value) {
            this.fieldValue = value & bit_mask;
        }

        public int increment() {
            setValue(fieldValue + 1);
            return this.fieldValue;
        }

        public int decrement() {
            setValue(fieldValue - 1);
            return this.fieldValue;
        }

        public int getBitMask() {
            return bit_mask;
        }

        public int getMaxValue() {
            return getBitMask();
        }

        public int getValue() {
            return this.fieldValue;
        }

        public Field joinRight(Field otherField) {
            return new Field(null, this.bitSize + otherField.bitSize, (this.fieldValue << otherField.bitSize) | otherField.fieldValue);
        }

        public Field joinLeft(Field f) {
            return new Field(null, this.bitSize + f.bitSize, (f.fieldValue << this.bitSize) | this.fieldValue);
        }

        private Bytes compile(Bytes header, int usedBits, int fieldCount) {
            Bytes padded = Bytes.from(fieldValue).resize(header.length());
            Bytes shifted = padded.leftShift((header.length() * Byte.SIZE) - usedBits - this.bitSize);
            Bytes combined = header.or(shifted);
            if (this.nextField == null || fieldCount == 0) {
                return combined;
            }
            return this.nextField.compile(combined, usedBits + this.bitSize, fieldCount - 1);
        }

        private Bytes compile(Bytes header, int fieldCount) {
            return compile(header, 0, fieldCount);
        }

        private void dismantle(Bytes header, int usedBits) {
            Bytes shift = header.rightShift((header.length() * Byte.SIZE) - usedBits - this.bitSize);
            this.fieldValue = shift.resize(Integer.BYTES).toInt() & this.bit_mask;
            if (this.nextField == null) {
                return;
            }
            this.nextField.dismantle(header, usedBits + this.bitSize);
        }

        private void dismantle(Bytes header) {
            dismantle(header, 0);
        }

        private void clearAll() {
            this.fieldValue = 0;
            if (this.nextField == null) {
                return;
            }
            nextField.clearAll();
        }

        @Override
        public String toString() {
            return toString(0);
        }

        private String toString(int padding) {
            return String.format("%-" + padding + "s: bits: %2d, value: 0x%X", '\'' + name + '\'', bitSize, fieldValue);
        }

        private String toStringNested(int padding) {

            if (this.nextField == null) {
                return toString(padding);
            }
            return toString(padding) + '\n' + nextField.toStringNested(padding);
        }

    }

}
