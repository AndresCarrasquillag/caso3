import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
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
                    out.writeObject(publicKey);

                    byte[] retoBytes = (byte[]) inputStream.readObject();
                    System.out.println("Reto recibido: " + new BigInteger(retoBytes));

                    Signature firma = Signature.getInstance("SHA256withRSA");
                    firma.initSign(privateKey);
                    firma.update(retoBytes);
                    byte[] firm = firma.sign();
                    out.writeObject(firm);
                    System.out.println("Firma enviada.");

                    // Implementación adicional para Diffie-Hellman y otros pasos según necesario
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
