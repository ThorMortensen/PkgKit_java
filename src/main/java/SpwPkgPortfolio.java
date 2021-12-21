import PackageKit.PackageKitChecksums;
import PackageKit.PackageKit;

public class SpwPkgPortfolio {

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


    public SpwPkgPortfolio() {
        /*******************
         *      Common
         ******************/
        PROTOCOL_ID.addField("logicAddress", 8);
        PROTOCOL_ID.addField("protocolId", 8);

        /*******************
         *      RMAP
         ******************/
        RMAP_INSTRUCTION.addField("reserved", 1);
        RMAP_INSTRUCTION.addField("commandReply", 1);
        RMAP_INSTRUCTION.addField("isWrite", 1);
        RMAP_INSTRUCTION.addField("verify", 1);
        RMAP_INSTRUCTION.addField("reply", 1);
        RMAP_INSTRUCTION.addField("increment", 1);
        RMAP_INSTRUCTION.addField("replyAddress", 2);

        RMAP_COMMON_ALL.addFieldsFrom(PROTOCOL_ID);
        RMAP_COMMON_ALL.addFieldsFrom(RMAP_INSTRUCTION);
        RMAP_COMMON_ALL.addField("statusKey", 8);
        RMAP_COMMON_ALL.addField("initOrTargetAddress", 8);
        RMAP_COMMON_ALL.addField("transId", 16);

        RMAP_COMMON_INITIATOR.addFieldsFrom(RMAP_COMMON_ALL);
        RMAP_COMMON_INITIATOR.addField("extendedAddress", 8);
        RMAP_COMMON_INITIATOR.addField("address", 32);
        RMAP_COMMON_INITIATOR.addField("dataLength", 24);

        RMAP_WRITE.addFieldsFrom(RMAP_COMMON_INITIATOR);
        RMAP_WRITE_REPLY.addFieldsFrom(RMAP_COMMON_ALL);

        RMAP_READ.addFieldsFrom(RMAP_COMMON_INITIATOR);
        RMAP_READ_REPLY.addFieldsFrom(RMAP_COMMON_ALL);
        RMAP_READ_REPLY.addField("reserved", 8);
        RMAP_READ_REPLY.addField("dataLength", 24);

        //        /*******************
//         *      PUS
//         ******************/
//        PUS_PRIME_HEADER.addField("pkgVersion", 3);
//        PUS_PRIME_HEADER.addField("pkgType", 1);
//        PUS_PRIME_HEADER.addField("secondHeaderFlag", 1);
//        PUS_PRIME_HEADER.addField("apid", 11);
//        PUS_PRIME_HEADER.addField("seqFlags", 2);
//        PUS_PRIME_HEADER.addField("seqCounter", 14);
//        PUS_PRIME_HEADER.addField("length", 16);
//
//        PUS_TC.addFieldsFrom(PUS_PRIME_HEADER);
//        PUS_TC.addField("pusVersion", 4);
//        PUS_TC.addField("ackFlags", 4);
//        PUS_TC.addField("service", 8);
//        PUS_TC.addField("subService", 8);
//        PUS_TC.addField("sourceId", 16);
//
//        PUS_TM.addFieldsFrom(PUS_PRIME_HEADER);
//        PUS_TM.addField("pusVersion", 4);
//        PUS_TM.addField("timeRefStatus", 4);
//        PUS_TM.addField("service", 8);
//        PUS_TM.addField("subService", 8);
//        PUS_TM.addField("typeSeqCounter", 16);
//        PUS_TM.addField("destId", 16);
//
//
//        /*******************
//         *      CPTP
//         ******************/
//        CPTP.addFieldsFrom(PROTOCOL_ID);
//        CPTP.addField("reserved", 8);
//        CPTP.addField("userApplication", 8);
//
//        /*******************
//         *      NATIVE
//         ******************/
//        NATIVE.addFieldsFrom(CPTP);

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


}
