import at.favre.lib.bytes.Bytes;
import com.rovsing.msr_ero.sis.spw.SpwPkgFactory;
import com.rovsing.packetRouting.PackageKit.PackageKit;

import java.util.Locale;

public class Main {


    public static void main(String[] args) {
        SpwPkgFactory pkgFactory = new SpwPkgFactory();

        PackageKit cptpIn = pkgFactory.new_CPTP();
        PackageKit pusTc = pkgFactory.new_PUS_TC();
        cptpIn.fromBytes(Bytes.parseHex("0002010138014002000A1109010100000000706B"));
        pusTc.fromBytes(cptpIn.getPayload());

        System.out.println(cptpIn);
        System.out.println(pusTc);

    }

}