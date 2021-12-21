import PackageKit.PackageKit;

public class Main {


    public static void main(String[] args) {
        SpwPkgPortfolio pkgFactory = new SpwPkgPortfolio();

        PackageKit rmapWrite = pkgFactory.new_RMAP_WRITE();
        rmapWrite.getField("reserved").setValue(1);
        rmapWrite.getField("replyAddress").setValue(1);

        System.out.println(rmapWrite);
        PackageKit inst = rmapWrite.getSubPkg("instruction");
        System.out.println(inst);

    }

}