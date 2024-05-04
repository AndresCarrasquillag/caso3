import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class Servidor {
    public static final int PUERTO = 3400;
    private static PrivateKey privateKey;
    public static PublicKey publicKey;

    public static void main(String args[]) {
        ServerSocket ss = null;
        try {
            ss = new ServerSocket(PUERTO);
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair pair = keyGen.generateKeyPair();
            privateKey = pair.getPrivate();
            publicKey = pair.getPublic();
            System.out.println("Servidor listo y escuchando en el puerto " + PUERTO);

            while (true) {
                try (Socket socket = ss.accept();
                     
                     ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                     ObjectInputStream inputStream = new ObjectInputStream(socket.getInputStream())) {
                    // ENVIAR LLAVE PUBLICA AL MANIN
                    out.writeObject(publicKey);

                    //PUNTO 2 Y 3
                    byte[] retoBytes = (byte[]) inputStream.readObject();
                    System.out.println("Reto recibido: " + new BigInteger(retoBytes));
                    Signature firma = Signature.getInstance("SHA256withRSA");
                    firma.initSign(privateKey);
                    firma.update(retoBytes);
                    byte[] firm = firma.sign();
                    out.writeObject(firm);
                    System.out.println("Firma enviada.");

                    //PUNTO 6
                    BigInteger[] params = DiffieHallman.generarParams();

                    //PUNTO 7
                    out.writeObject(params[0]);
                    out.writeObject(params[1]);
                    out.writeObject(params[2]);
                    ByteBuffer buffer = ByteBuffer.allocate(3 * Long.BYTES);
                    buffer.put(params[0].toByteArray());
                    buffer.put(params[1].toByteArray());
                    buffer.put(params[2].toByteArray());
                    byte[] concatenated = buffer.array();
                    Signature firmaDH = Signature.getInstance("SHA256withRSA");
                    firmaDH.initSign(privateKey);
                    firmaDH.update(concatenated);
                    byte[] signature = firmaDH.sign();
                    out.writeObject(signature);
                } catch (Exception e) {
                    System.out.println("Error durante la sesión del cliente: " + e.getMessage());
                }
            }
        } catch (IOException | NoSuchAlgorithmException e) {
            System.out.println("Error al iniciar el servidor: " + e.getMessage());
        } finally {
            if (ss != null) {
                try {
                    ss.close();
                } catch (IOException e) {
                    System.out.println("Error al cerrar el servidor: " + e.getMessage());
                }
            }
        }
    }
}
