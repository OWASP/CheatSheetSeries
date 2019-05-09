import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;

// PLEASE RENAME THIS FILE TO PBKDF2ItEval.java BEFORE COMPILING.
public class PBKDF2ItEval {

    public static void main(String[] args) throws Exception {
        //Initialization
        SecureRandom rnd = new SecureRandom();
        byte[] salt = new byte[64];
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        char[] password = "mypassword".toCharArray();
        //Test for 10.000 iterations
        rnd.nextBytes(salt);
        PBEKeySpec spec = new PBEKeySpec(password, salt, 10000, 256);
        long start = System.currentTimeMillis();
        skf.generateSecret(spec);
        System.out.printf("Computation time is %s milliseconds for 10.000 iterations with a key size of 256 bits\n", (System.currentTimeMillis() - start));
        //Test for 100.000 iterations
        rnd.nextBytes(salt);
        spec = new PBEKeySpec(password, salt, 100000, 256);
        start = System.currentTimeMillis();
        skf.generateSecret(spec);
        System.out.printf("Computation time is %s milliseconds for 100.000 iterations with a key size of 256 bits\n", (System.currentTimeMillis() - start));
        //Test for 500.000 iterations
        rnd.nextBytes(salt);
        spec = new PBEKeySpec(password, salt, 500000, 256);
        start = System.currentTimeMillis();
        skf.generateSecret(spec);
        System.out.printf("Computation time is %s milliseconds for 500.000 iterations with a key size of 256 bits\n", (System.currentTimeMillis() - start));
        //Test for 1.000.000 iterations
        rnd.nextBytes(salt);
        spec = new PBEKeySpec(password, salt, 1000000, 256);
        start = System.currentTimeMillis();
        skf.generateSecret(spec);
        System.out.printf("Computation time is %s milliseconds for 1.000.000 iterations with a key size of 256 bits\n", (System.currentTimeMillis() - start));
    }
}