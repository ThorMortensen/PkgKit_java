import PackageKit.PackageKit;
import at.favre.lib.bytes.Bytes;

public class Main {


    public static void main(String[] args) {
        SpwPkgPortfolio pkgFactory = new SpwPkgPortfolio();

        PackageKit rmapWrite = pkgFactory.new_RMAP_WRITE();
        rmapWrite.getField("reserved").setValue(1);
        rmapWrite.getField("verify").setValue(0x801);
        rmapWrite.getField("replyAddress").setValue(1);

        System.out.println(rmapWrite);
        PackageKit inst = rmapWrite.getSubPkg("instruction");
        System.out.println(inst);
        inst.getField("increment").setValue(1);
        System.out.println(rmapWrite);


        inst.fromBytes(Bytes.from(0xff).resize(1));
        System.out.println(inst);

//        rmapWrite.getField("increment").setValue(1);

//        0xff
        System.out.println(rmapWrite);


        System.out.println("inst: " + inst.getHeader());

    }

}