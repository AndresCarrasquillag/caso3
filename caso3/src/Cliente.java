import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

public class Cliente {
    public static final int PUERTO = 3400;
    public static final String SERVIDOR = "localhost";

    public static void main(String[] args) {
        Socket socket = null;
        try {
            socket = new Socket(SERVIDOR, PUERTO);
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            // Recibir la clave pública del servidor
            PublicKey publicKey = (PublicKey) in.readObject();

            // Generar y enviar el reto
            SecureRandom random = new SecureRandom();
            BigInteger reto = new BigInteger(1024, random);
            byte[] retoBytes = reto.toByteArray();
            out.writeObject(retoBytes);

            // Recibir y verificar la firma del reto
            byte[] firmaServidor = (byte[]) in.readObject();
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(retoBytes);
            System.out.println(signature.verify(firmaServidor) ? "OK" : "ERROR");

            // Procesos DH
            BigInteger g = (BigInteger) in.readObject();
            BigInteger p = (BigInteger) in.readObject();
            BigInteger gxmodp = (BigInteger) in.readObject();
            byte[] firmaDH = (byte[]) in.readObject();

            // Verificar firma DH
            signature.update(g.toByteArray());
            signature.update(p.toByteArray());
            signature.update(gxmodp.toByteArray());
            System.out.println(signature.verify(firmaDH) ? "OK" : "ERROR");

        } catch (Exception e) {
            System.out.println("Excepción: " + e.getMessage());
        } finally {
            try {
                if (socket != null) socket.close();
            } catch (IOException e) {
                System.out.println("Error al cerrar el socket: " + e.getMessage());
            }
        }
    }
}

