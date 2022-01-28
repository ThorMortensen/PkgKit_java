package com.rovsing.msr_ero.sis.spw;

import com.rovsing.packetRouting.PackageKit.PackageKit;
import com.rovsing.packetRouting.PackageKit.PackageKitChecksums;

public class SpwPkgFactory {

    private static final PackageKit PUS_TC = new PackageKit("PUS_TC", PackageKitChecksums.crc16_std_PUS_ECSS_E_ST_70_41C_2016());
    private static final PackageKit PUS_TM = new PackageKit("PUS_TM", PackageKitChecksums.crc16_std_PUS_ECSS_E_ST_70_41C_2016());
    private static final PackageKit CPTP = new PackageKit("CPTP");
    private static final PackageKit NATIVE = new PackageKit("NATIVE");
    private static final PackageKit RMAP_WRITE = new PackageKit("RMAP_WRITE", PackageKitChecksums.crc8_RMAP_ECSS_E_ST_50_52C_2010(), true);
    private static final PackageKit RMAP_WRITE_REPLY = new PackageKit("RMAP_WRITE_REPLY", PackageKitChecksums.crc8_RMAP_ECSS_E_ST_50_52C_2010(), true);
    private static final PackageKit RMAP_READ = new PackageKit("RMAP_READ", PackageKitChecksums.crc8_RMAP_ECSS_E_ST_50_52C_2010(), true);
    private static final PackageKit RMAP_READ_REPLY = new PackageKit("RMAP_READ_REPLY", PackageKitChecksums.crc8_RMAP_ECSS_E_ST_50_52C_2010(), true);

    /*******************
     *  Building Blocks
     ******************/
    // Common fo all
    private static final PackageKit PROTOCOL_ID = new PackageKit("PID");
    // PUS stuff
    private static final PackageKit PUS_PRIME_HEADER = new PackageKit("PUS_PRIME_HEADER");
    // RMAP stuff
    private static final PackageKit RMAP_INSTRUCTION = new PackageKit("instruction");
    private static final PackageKit RMAP_COMMON_ALL = new PackageKit("commonAll");
    private static final PackageKit RMAP_COMMON_INITIATOR = new PackageKit("rmapCommonInitiator");


    public SpwPkgFactory() {
        /*******************
         *      Common
         ******************/
        PROTOCOL_ID.addField("logicAddress", 8);
        PROTOCOL_ID.addField("protocolId", 8);

        /*******************
         *      PUS
         ******************/
        PUS_PRIME_HEADER.addField("pkgVersion", 3);
        PUS_PRIME_HEADER.addField("pkgType", 1);
        PUS_PRIME_HEADER.addField("secondHeaderFlag", 1);
        PUS_PRIME_HEADER.addField("apid", 11);
        PUS_PRIME_HEADER.addField("seqFlags", 2);
        PUS_PRIME_HEADER.addField("seqCounter", 14);

        PUS_TC.addFieldsFrom(PUS_PRIME_HEADER);
        PUS_TC.addField("length", 16); // Set length here to use prime header in TM[1,1 and 7]

        PUS_TC.addField("pusVersion", 4);
        PUS_TC.addField("ackFlags", 4);
        PUS_TC.addField("service", 8);
        PUS_TC.addField("subService", 8);
        PUS_TC.addField("sourceId", 16);

        PUS_TM.addFieldsFrom(PUS_PRIME_HEADER);
        PUS_TM.addField("length", 16);
        PUS_TM.getField("pkgType").setValue(0);


        PUS_TM.addField("pusVersion", 4);
        PUS_TM.addField("timeRefStatus", 4);
        PUS_TM.addField("service", 8);
        PUS_TM.addField("subService", 8);
        PUS_TM.addField("typeSeqCounter", 16);
        PUS_TM.addField("destId", 16);
//        PUS_TM.addField("time", 7 * 8);

        /*******************
         *      CPTP
         ******************/
        CPTP.addFieldsFrom(PROTOCOL_ID);
        CPTP.getField("protocolId").setValue(2);
        CPTP.addField("reserved", 8);
        CPTP.addField("userApplication", 8);

        /*******************
         *      NATIVE
         ******************/
        NATIVE.addFieldsFrom(CPTP);
        NATIVE.getField("protocolId").setValue(240);

        /*******************
         *      RMAP
         ******************/
        RMAP_INSTRUCTION.addField("reserved", 1);
        RMAP_INSTRUCTION.addField("isCommand", 1);
        RMAP_INSTRUCTION.addField("isWrite", 1);
        RMAP_INSTRUCTION.addField("verify", 1);
        RMAP_INSTRUCTION.addField("reply", 1);
        RMAP_INSTRUCTION.addField("increment", 1);
        RMAP_INSTRUCTION.addField("replyAddressLength", 2);

        RMAP_COMMON_ALL.addFieldsFrom(PROTOCOL_ID);
        RMAP_COMMON_ALL.getField("protocolId").setValue(1);
        RMAP_COMMON_ALL.addFieldsFrom(RMAP_INSTRUCTION);
        RMAP_COMMON_ALL.addField("statusKey", 8);
        RMAP_COMMON_ALL.addField("senderAddress", 8);
        RMAP_COMMON_ALL.addField("transId", 16);

        RMAP_COMMON_INITIATOR.addFieldsFrom(RMAP_COMMON_ALL);
        RMAP_COMMON_INITIATOR.addField("extendedAddress", 8);
        RMAP_COMMON_INITIATOR.addField("address", 32);
        RMAP_COMMON_INITIATOR.addField("dataLength", 24);

        /** Write */
        RMAP_WRITE.addFieldsFrom(RMAP_COMMON_INITIATOR);
        // Set values from config. PackageKit will truncate to bit-size thus no need to mask out bits
        // Values set here will be default values for all future instances of these packages.

        RMAP_WRITE_REPLY.addFieldsFrom(RMAP_COMMON_ALL);

        /** Read */
        RMAP_READ.addFieldsFrom(RMAP_COMMON_INITIATOR);

        RMAP_READ_REPLY.addFieldsFrom(RMAP_COMMON_ALL);
        RMAP_READ_REPLY.addField("reserved", 8);
        RMAP_READ_REPLY.addField("dataLength", 24);
    }

    public PackageKit new_PUS_TC() {
        return new PackageKit(PUS_TC);
    }

    public PackageKit new_PUS_TM() {
        return new PackageKit(PUS_TM);
    }

    public PackageKit new_NATIVE() {
        return new PackageKit(NATIVE);
    }

    public PackageKit new_CPTP() {
        return new PackageKit(CPTP);
    }

    public PackageKit new_RMAP_WRITE() {
        return new PackageKit(RMAP_WRITE);
    }

    public PackageKit new_RMAP_WRITE_REPLY() {
        return new PackageKit(RMAP_WRITE_REPLY);
    }

    public PackageKit new_RMAP_READ() {
        return new PackageKit(RMAP_READ);
    }

    public PackageKit new_RMAP_READ_REPLY() {
        return new PackageKit(RMAP_READ_REPLY);
    }

    public int getPusTMHeaderLength() {
        return 7;
    }


}
