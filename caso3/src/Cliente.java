import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

public class Cliente {
    private PublicKey publicKey;
    public static final int PUERTO = 3400;
    public static final String SERVIDOR = "localhost";

    public static void main(String args[]) throws IOException {
        Socket socket = null;
        try {
            socket = new Socket(SERVIDOR, PUERTO);
            ObjectInputStream inputStream = new ObjectInputStream(socket.getInputStream());
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            PublicKey llaveServ = (PublicKey) inputStream.readObject();

            // Punto 1
            SecureRandom random = new SecureRandom();
            System.out.println(".");
            BigInteger reto = new BigInteger(1024, random);
            out.writeObject(reto);
            // PUNTO 4
            byte[] firmaServ = (byte[]) inputStream.readObject();
            System.out.println("h");
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(llaveServ);
            byte[] retoBytes = reto.toByteArray();
            signature.update(retoBytes);
            System.out.println(retoBytes);
            System.out.println(reto);
            if (signature.verify(firmaServ)) {
                System.out.println("bien");
            } else {
                System.out.println("que mieee");
            }
            /*BigInteger retoServ = new BigInteger(CifradoAsimetrico.descifrar(llaveServ, "RSA/ECB/PKCS1Padding", r));
            if (retoServ.equals(reto)) {
                System.out.println("hola");
            } else {
                System.out.println("que mieee");
            }*/
            // descrifrar y si es igual a reto entonces envía ok

        } catch (Exception e) {
            // TODO: handle exception
        }
    }

    public Cliente(PublicKey publicKey, long p, long g, long x) {
        this.publicKey = publicKey;
    }
}
