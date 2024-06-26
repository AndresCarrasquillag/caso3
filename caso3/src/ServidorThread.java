import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ServidorThread extends Thread {
    private Socket socket;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public ServidorThread(Socket socket, PrivateKey privateKey, PublicKey publicKey) {
        this.socket = socket;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    @Override
    public void run() {
        try (
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            out.writeObject(publicKey);

            byte[] retoBytes = (byte[]) in.readObject();
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(retoBytes);
            byte[] firma = signature.sign();
            out.writeObject(firma);

            if("OK".equals(in.readObject())) {
                System.out.println("OK recibido");
                // Establecimiento de la conexión segura
                KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
                keyPairGen.initialize(1024);
                KeyPair serverKeyPair = keyPairGen.generateKeyPair();
                DHPublicKey serverPublicKey = (DHPublicKey) serverKeyPair.getPublic();
                BigInteger g = serverPublicKey.getParams().getG();
                BigInteger p = serverPublicKey.getParams().getP();
                BigInteger gxmodp = serverPublicKey.getY();

                SecureRandom random = new SecureRandom();
                byte[] iv = new byte[16];
                random.nextBytes(iv);

                out.writeObject(g);
                out.writeObject(p);
                out.writeObject(gxmodp);
                out.writeObject(iv);
                long startTimeFirma = System.currentTimeMillis();
                signature.update(g.toByteArray());
                signature.update(p.toByteArray());
                signature.update(gxmodp.toByteArray());
                byte[] firmaDH = signature.sign();
                long finalTimeFirma = System.currentTimeMillis();
                out.writeObject(firmaDH);

                if("OK".equals(in.readObject())) {
                    System.out.println("OK recibido");
                    BigInteger gymodp = (BigInteger) in.readObject();
                    KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
                    keyAgreement.init(serverKeyPair.getPrivate());
                    DHPublicKeySpec dhPubKeySpec = new DHPublicKeySpec(gymodp, p, g);
                    PublicKey clientPublicKey = KeyFactory.getInstance("DH").generatePublic(dhPubKeySpec);
                    keyAgreement.doPhase(clientPublicKey, true);
                    byte[] serverSecret = keyAgreement.generateSecret();
                    SecretKey serverAesKey = new SecretKeySpec(serverSecret, 0, 16, "AES");

                    MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
                    byte[] digest = sha512.digest(serverAesKey.getEncoded());
                    byte[] encryptionKey = new byte[32]; // para AES
                    byte[] hmacKey = new byte[32]; // para HMAC
                    System.arraycopy(digest, 0, encryptionKey, 0, 32);
                    System.arraycopy(digest, 32, hmacKey, 0, 32);

                    SecretKey aesKey = new SecretKeySpec(encryptionKey, "AES");
                    SecretKey hmacSha256Key = new SecretKeySpec(hmacKey, "HmacSHA256");

                    // Paso 12: Enviar "CONTINUAR" al cliente
                    out.writeObject("CONTINUAR");

                    // Paso 15 y 16: Recibir y verificar credenciales cifradas
                    byte[] encryptedCredentials = (byte[]) in.readObject();
                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    SecretKeySpec keySpec = new SecretKeySpec(aesKey.getEncoded(), "AES");
                    IvParameterSpec ivSpec = new IvParameterSpec(iv);
                    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
                    byte[] decryptedCredentials = cipher.doFinal(encryptedCredentials);
                    String credentials = new String(decryptedCredentials);

                    boolean credentialsValid = "usuario:contrasena".equals(credentials);
                    out.writeObject(credentialsValid ? "OK" : "ERROR");
                    System.out.println("Resultado de la verificación de credenciales: " + (credentialsValid ? "OK" : "ERROR"));

                    // Paso 19-21: Recibir consulta cifrada, verificar HMAC, procesar y responder
                    byte[] consultaCifrada = (byte[]) in.readObject();
                    byte[] hmacConsultaRecibido = (byte[]) in.readObject();

                    long startTimeConsulta = System.currentTimeMillis();
                    cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
                    byte[] consultaDescifrada = cipher.doFinal(consultaCifrada);
                    long finalTimeConsulta = System.currentTimeMillis();
                    System.out.println("Consulta recibida y descifrada: " + new String(consultaDescifrada));

                    long startTimeHMAC = System.nanoTime();
                    Mac mac = Mac.getInstance("HmacSHA256");
                    mac.init(hmacSha256Key);
                    byte[] hmacCalculado = mac.doFinal(consultaDescifrada);
                    if (MessageDigest.isEqual(hmacConsultaRecibido, hmacCalculado)) {
                        System.out.println("HMAC verificado con éxito.");
                    } else {
                        System.out.println("Error de verificación HMAC.");
                    }
                    long finalTimeHMAC = System.nanoTime();

                    String respuesta = "Saldo: $1000";
                    byte[] respuestaBytes = respuesta.getBytes();
                    cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
                    byte[] respuestaCifrada = cipher.doFinal(respuestaBytes);
                    out.writeObject(respuestaCifrada);
                    
                    byte[] hmacRespuesta = mac.doFinal(respuestaBytes);
                    out.writeObject(hmacRespuesta);
                    System.out.println("Respuesta y HMAC enviados al cliente.");
                    long duracionFirma = finalTimeFirma-startTimeFirma;
                    long duracionConsulta = finalTimeConsulta-startTimeConsulta;
                    System.out.println("Tiempo generar firma: " + duracionFirma);
                    System.out.println("Tiempo descrifrar consulta: " + duracionConsulta);
                    long tiempoAutenticacion = finalTimeHMAC-startTimeHMAC;
                    System.out.println("tiempo HMAC: "+tiempoAutenticacion);
                }   
            }
        } catch (Exception e) {
            System.out.println("Error durante la sesión del cliente: " + e.getMessage());
        }
    }

    

}
