import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Arrays;

public class CifradoSimetrico {
    private static final String ALGORITMO = "AES";
    private static final String TRANSFORMACION = "AES/CBC/PKCS5Padding";

    public static SecretKey generarClaveSimetrica() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITMO);
        SecureRandom secureRandom = new SecureRandom();
        keyGenerator.init(256, secureRandom); 
        return keyGenerator.generateKey();
    }

    public static byte[] cifrar(SecretKey llave, String texto) {
        try {
            Cipher cifrador = Cipher.getInstance(TRANSFORMACION);
            byte[] textoClaro = texto.getBytes();
            byte[] iv = new byte[cifrador.getBlockSize()];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv); // Genera un IV aleatorio.
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cifrador.init(Cipher.ENCRYPT_MODE, llave, ivSpec);
            byte[] textoCifrado = cifrador.doFinal(textoClaro);
            byte[] textoCifradoConIv = new byte[iv.length + textoCifrado.length];
            System.arraycopy(iv, 0, textoCifradoConIv, 0, iv.length);
            System.arraycopy(textoCifrado, 0, textoCifradoConIv, iv.length, textoCifrado.length);
            return textoCifradoConIv;
        } catch (Exception e) {
            System.out.println("Exception: " + e.getMessage());
            return null;
        }
    }

    public static byte[] descifrar(SecretKey llave, byte[] textoCifradoConIv) {
        try {
            Cipher cifrador = Cipher.getInstance(TRANSFORMACION);
            byte[] iv = Arrays.copyOfRange(textoCifradoConIv, 0, cifrador.getBlockSize());
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            byte[] textoCifrado = Arrays.copyOfRange(textoCifradoConIv, cifrador.getBlockSize(), textoCifradoConIv.length);
            cifrador.init(Cipher.DECRYPT_MODE, llave, ivSpec);
            return cifrador.doFinal(textoCifrado);
        } catch (Exception e) {
            System.out.println("Exception: " + e.getMessage());
            return null;
        }
    }
}





