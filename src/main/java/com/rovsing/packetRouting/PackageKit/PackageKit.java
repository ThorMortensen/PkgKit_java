package com.rovsing.packetRouting.PackageKit;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.bytes.BytesTransformer;
import at.favre.lib.bytes.BytesTransformer.ResizeTransformer;
import lombok.Getter;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.NoSuchElementException;
import java.util.Optional;


public class PackageKit {
    private final HashMap<String, Field> headerComposition;
    private final HashMap<String, PackageKit> headerSubFieldMap;
    private final boolean useSeparateChecksum;
    private Field head;
    private Field tail;
    private int headerBitSum = 0;

    @Getter
    private String pkgName;
    private Bytes payload;
    private Bytes dismantledPkg;
    private final int pecSizeHeader;
    private final int pecSizePayload;
    private int fieldCount = 0;

    private int ppPad = 0;
    private final com.rovsing.packetRouting.PackageKit.PackageKitChecksums checksum;

    public PackageKit(String pkgName, com.rovsing.packetRouting.PackageKit.PackageKitChecksums checksum, boolean useSeparateHeaderChecksum) {
        this.pkgName = pkgName;
        headerComposition = new HashMap<>();
        headerSubFieldMap = new LinkedHashMap<>();
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

    public PackageKit(String pkgName, com.rovsing.packetRouting.PackageKit.PackageKitChecksums checksum) {
        this(pkgName, checksum, false);
    }

    public PackageKit(String pkgName) {
        this(pkgName, null, false);
    }

    public PackageKit(PackageKit from, String cloneName) {
        this(cloneName, from.checksum, from.useSeparateChecksum);
        merge(from);
    }

    public PackageKit(PackageKit from) {
        this(from, from.pkgName);
    }

    // Shadow copy
    private PackageKit(String pkgName, Field head, Field tail) {
        this(pkgName, null, false);
        this.head = head;
        this.tail = tail;
        Field walker = head;
        while (walker != tail) {
            ppPad = Integer.max(walker.name.length(), ppPad);
            headerComposition.put(walker.name, walker);
            headerBitSum += walker.bitSize;
            walker = walker.nextField;
        }
        headerComposition.put(walker.name, walker);
        headerBitSum += walker.bitSize;
    }

    private void merge(PackageKit from) {
        cloneFields(from);
        from.headerSubFieldMap.forEach((key, value) -> {
            headerSubFieldMap.put(key, new PackageKit(value.pkgName, headerComposition.get(value.head.name), headerComposition.get(value.tail.name)));
        });
    }

    /***************************
     *       Fields
     **************************/
    public PackageKit addField(String fieldName, int bitLength, int fieldValue) {
        ppPad = Integer.max(fieldName.length(), ppPad);
        headerBitSum += bitLength;
        fieldCount++;
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
        ppPad = Integer.max(from.ppPad, ppPad);
        merge(from);
        headerSubFieldMap.put(from.pkgName, new PackageKit(from.pkgName, headerComposition.get(from.head.name), headerComposition.get(from.tail.name)));

        return this;
    }

    public Field getField(String name) {
        return Optional.ofNullable(headerComposition.get(name)).orElseThrow(() -> new NoSuchElementException("Field: " + name + " not found in " + pkgName));
    }

    public PackageKit getSubPkg(String name) {
        return headerSubFieldMap.get(name);
    }

    public PackageKit setSubPkg(String name, Bytes value) {
        return headerSubFieldMap.get(name).fromBytes(value);
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
    private Bytes getHeaderChecksum(Bytes header) {
        if (!useSeparateChecksum || checksum == null || header.isEmpty()) {
            return Bytes.empty();
        }
        return header.transform(checksum);
    }

    public Bytes getHeaderChecksum() {
        if (checksum == null) {
            return Bytes.empty();
        }
        return compileHeader().resize(checksum.digestByteSize(), ResizeTransformer.Mode.RESIZE_KEEP_FROM_MAX_LENGTH);
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
            return fromBytesHeaderOnly(pkgBytes);
        }

        head.dismantle(pkgBytes, 0, tail);
        payload = pkgBytes.copy(headerSize(), pkgBytes.length() - headerSize());
        dismantledPkg = pkgBytes;
        return this;
    }

    public PackageKit fromBytesHeaderOnly(Bytes pkgBytes) {
        assertHeaderSize();
        dismantledPkg = pkgBytes.resize(headerSize(), ResizeTransformer.Mode.RESIZE_KEEP_FROM_ZERO_INDEX);
        head.dismantle(dismantledPkg, tail);
        payload = Bytes.empty();
        return this;
    }

    public Bytes toBytes() {
        assertHeaderSize();
        dismantledPkg = Bytes.empty();
//        if (useSeparateChecksum) {
//            return compileHeader().append(payload).append(getPayloadChecksum());
//        }
        return compileHeader().append(payload).append(getChecksum());
    }

    /***************************
     *         Info
     **************************/
    public int size() {
        return dismantledPkg.isEmpty() ? headerSize() + payloadSize() : dismantledPkg.length();
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
        String pkg;
        String type;
        if (dismantledPkg.isEmpty()) {
            type = "Compiled Package : ";
            pkg = toBytes().encodeHex().toUpperCase();
        } else {
            type = "Dismantled Package : ";
            pkg = dismantledPkg.encodeHex().toUpperCase();
        }
        return String.format("%s%s\n%" + (type.length() + (headerSize() * 2) + 8) + "s", type, pkg, "header | payload");
    }

    @Override
    public String toString() {


        return "=== PackageKit: '" + pkgName + '\'' + " ===\n" +
                "Package size: " + size() + " bytes" + '\n' +
                "Payload size: " + payloadSize() + " bytes" + '\n' +
                "Field size  : " + headerSize() + " bytes" + '\n' +
                "Field count : " + headerComposition.size() + '\n' +
                "Components  : " + headerSubFieldMap.keySet() + '\n' +
                "--- Header composition ---" + '\n' +
                head.toStringNested(ppPad + 3, tail) + '\n' +
                "--- Pkg composition (hex) ---" + '\n' +
                "Header  : " + compileHeader().encodeHex().toUpperCase() + '\n' +
                "Payload : " + payload.append().encodeHex().toUpperCase() + '\n' +
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
        Bytes header = head.compile(Bytes.allocate((headerBitSum / Byte.SIZE)), tail);
        return header.append(getHeaderChecksum(header));
    }

    private void cloneFields(PackageKit from) {
        Field head = from.head;
        while (head != from.tail) {
            addField(head.name, head.bitSize, head.fieldValue);
            head = head.nextField;
        }
        addField(head.name, head.bitSize, head.fieldValue);
    }

    public void setPkgName(String name) {
        this.pkgName = name;
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

        public void setValue(Field from) {
            this.fieldValue = from.getValue() & bit_mask;
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

        private Bytes compile(Bytes header, int usedBits, Field endField) {
            Bytes padded = Bytes.from(fieldValue).resize(header.length());
            Bytes shifted = padded.leftShift((header.length() * Byte.SIZE) - usedBits - this.bitSize);
            Bytes combined = header.or(shifted);
            if (this.nextField == null || endField == this) {
                return combined;
            }
            return this.nextField.compile(combined, usedBits + this.bitSize, endField);
        }

        private Bytes compile(Bytes header, Field endField) {
            return compile(header, 0, endField);
        }

        private void dismantle(Bytes header, int usedBits, Field endField) {
            Bytes shift = header.rightShift((header.length() * Byte.SIZE) - usedBits - this.bitSize);
            this.fieldValue = shift.resize(Integer.BYTES).toInt() & this.bit_mask;
            if (this.nextField == null || endField == this) {
                return;
            }
            this.nextField.dismantle(header, usedBits + this.bitSize, endField);
        }

        private void dismantle(Bytes header, Field endField) {
            dismantle(header, 0, endField);
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

        private String toStringNested(int padding, Field tail) {

            if (this == tail) {
                return toString(padding);
            }
            return toString(padding) + '\n' + nextField.toStringNested(padding, tail);
        }

    }

}
