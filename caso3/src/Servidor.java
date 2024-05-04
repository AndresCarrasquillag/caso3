import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Servidor {
    public static final int PUERTO = 3400;
    private static PrivateKey privateKey;
    public static PublicKey publicKey;

    public static void main(String[] args) {
        ServerSocket serverSocket = null;
        try {
            serverSocket = new ServerSocket(PUERTO);
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair pair = keyGen.generateKeyPair();
            privateKey = pair.getPrivate();
            publicKey = pair.getPublic();

            System.out.println("Servidor listo y escuchando en el puerto " + PUERTO);

            while (true) {
                try (Socket socket = serverSocket.accept();
                     ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                     ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

                    out.writeObject(publicKey);

                    byte[] retoBytes = (byte[]) in.readObject();
                    Signature signature = Signature.getInstance("SHA256withRSA");
                    signature.initSign(privateKey);
                    signature.update(retoBytes);
                    byte[] firma = signature.sign();
                    out.writeObject(firma);

                    // Simulación de parámetros DH
                    KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
                    keyPairGen.initialize(1024);
                    KeyPair serverKeyPair = keyPairGen.generateKeyPair();
                    DHPublicKey serverPublicKey = (DHPublicKey) serverKeyPair.getPublic();
                    BigInteger g = serverPublicKey.getParams().getG();
                    BigInteger p = serverPublicKey.getParams().getP();
                    BigInteger gxmodp = serverPublicKey.getY();
                    
                    // Enviar G, P y gxmodp
                    out.writeObject(g);
                    out.writeObject(p);
                    out.writeObject(gxmodp);
                    signature.update(g.toByteArray());
                    signature.update(p.toByteArray());
                    signature.update(gxmodp.toByteArray());
                    byte[] firmaDH = signature.sign();
                    out.writeObject(firmaDH);

                    

                    // Recibir gxmody y calcular clave secreta
                    BigInteger gymodp = (BigInteger) in.readObject();
                    KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
                    keyAgreement.init(serverKeyPair.getPrivate());
                    DHPublicKeySpec dhPubKeySpec = new DHPublicKeySpec(gymodp, p, g);
                    PublicKey clientPublicKey = KeyFactory.getInstance("DH").generatePublic(dhPubKeySpec);
                    keyAgreement.doPhase(clientPublicKey, true);
                    byte[] serverSecret = keyAgreement.generateSecret();
                    SecretKey serverAesKey = new SecretKeySpec(serverSecret, 0, 16, "AES");
                    System.out.println(serverAesKey);

                } catch (Exception e) {
                    System.out.println("Error durante la sesión del cliente: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            System.out.println("Error al iniciar el servidor: " + e.getMessage());
        } finally {
            try {
                if (serverSocket != null) serverSocket.close();
            } catch (IOException e) {
                System.out.println("Error al cerrar el servidor: " + e.getMessage());
            }
        }
    }
}


