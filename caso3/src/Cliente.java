import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.PublicKey;
import java.security.SecureRandom;

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
            // Punto 1
            SecureRandom random = new SecureRandom();
            System.out.println(".");
            BigInteger reto = new BigInteger(1024, random);
            out.writeObject(reto);
            // PUNTO 4
            byte[] r = (byte[] )inputStream.readObject();
            // descrifrar y si es igual a reto entonces envía ok

        } catch (Exception e) {
            // TODO: handle exception
        }
    }

    public Cliente(PublicKey publicKey, long p, long g, long x) {
        this.publicKey = publicKey;
    }
}
