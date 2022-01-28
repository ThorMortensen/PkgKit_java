import at.favre.lib.bytes.Bytes;
import com.rovsing.packetRouting.PackageKit.PackageKit;
import lombok.experimental.var;

import java.util.Locale;

public class Main {


    public static void main(String[] args) {
        SpwPkgFactory pkgFactory = new SpwPkgFactory();
        Bytes payload = Bytes.parseHex("1234");

        PackageKit rmapWrite = pkgFactory.new_RMAP_WRITE();
        PackageKit rmapWriteDBP = pkgFactory.new_RMAP_WRITE();
        rmapWrite.getField("logicAddress").setValue(0xff);
        rmapWrite.getField("address").setValue(0x1);
        rmapWrite.getField("transId").setValue(1);
        rmapWrite.getField("dataLength").setValue(1);
        rmapWrite.setPayload(Bytes.from(payload));
        System.out.println("SpwHandler.spwRMAPWrite");
        System.out.println(rmapWrite.size());

        System.out.println(rmapWrite);
        System.out.println(rmapWrite.toBytes().encodeHex().toUpperCase(Locale.ROOT));

        System.out.println(rmapWrite.size());
        System.out.println(rmapWrite.toBytes().length());

//        rmapWriteDBP.toBytes();
//        System.out.println(rmapWrite);
        System.out.println(rmapWriteDBP.fromBytes(rmapWrite.toBytes()));

//        SpwPkgFactory pkgFactory = new SpwPkgFactory();
//
//        PackageKit rmapWrite = pkgFactory.new_RMAP_WRITE();
//        rmapWrite.getField("reserved").setValue(1);
//        rmapWrite.getField("verify").setValue(0x801);
//        rmapWrite.getField("replyAddress").setValue(1);
//
//        System.out.println(rmapWrite);
//        PackageKit inst = rmapWrite.getSubPkg("instruction");
//        System.out.println(inst);
//        inst.getField("increment").setValue(1);
//        System.out.println(rmapWrite);
//
//
//        inst.fromBytes(Bytes.from(0xff).resize(1));
//        System.out.println(inst);
//
////        rmapWrite.getField("increment").setValue(1);
//
////        0xff
//        System.out.println(rmapWrite);
//
//
//        System.out.println("inst: " + inst.getHeader());

    }

}