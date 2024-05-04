import java.io.ByteArrayOutputStream;
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
            if (signature.verify(firmaServ)) {
                System.out.println("OK");
            } else {
                System.out.println("ERROR");
            }
            BigInteger g = (BigInteger)inputStream.readObject();
            BigInteger p = (BigInteger)inputStream.readObject();
            BigInteger gxmodp = (BigInteger)inputStream.readObject();
            byte[] firmaDH = (byte[]) inputStream.readObject();
            ByteBuffer buffer = ByteBuffer.allocate(3 * Long.BYTES);
            buffer.put(g.toByteArray());
            buffer.put(p.toByteArray());
            buffer.put(gxmodp.toByteArray());
            byte[] concatenated = buffer.array();
            Signature signatureDH = Signature.getInstance("SHA256withRSA");
            signatureDH.initVerify(publicKey);
            signatureDH.update(concatenated);
            if (signatureDH.verify(firmaDH)) {
                System.out.println("OK");
            } else {
                System.out.println("ERROR");
            }

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
