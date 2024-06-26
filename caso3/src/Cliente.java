import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Cliente implements Runnable {
    public static final int PUERTO = 3400;
    public static final String SERVIDOR = "localhost";

    public static void main(String[] args) {
        System.out.println("Ingrese el número de clientes a lanzar:");
        Scanner scanner = new Scanner(System.in);
        int numClientes = scanner.nextInt();
        scanner.close();

        for (int i = 0; i < numClientes; i++) {
            Thread thread = new Thread(new Cliente());
            thread.start();
        } 
    }

    @Override
    public void run() {
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
            long startTimeFirma = System.nanoTime();
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(retoBytes);
            String verify = (signature.verify(firmaServidor) ? "OK" : "ERROR");
            long finalTimeFirma = System.nanoTime();
            System.out.println(verify);
            out.writeObject(verify);
            verify = "";

            // Procesos DH
            BigInteger g = (BigInteger) in.readObject();
            BigInteger p = (BigInteger) in.readObject();
            BigInteger gxmodp = (BigInteger) in.readObject();
            byte[] iv = (byte[]) in.readObject();
            byte[] firmaDH = (byte[]) in.readObject();

            // Verificar firma DH
            signature.update(g.toByteArray());
            signature.update(p.toByteArray());
            signature.update(gxmodp.toByteArray());

            verify = (signature.verify(firmaDH) ? "OK" : "ERROR");
            System.out.println(verify);
            out.writeObject(verify);

            // Enviar gmody
            long startTimeGy = System.nanoTime();
            DHParameterSpec dhSpecClient = new DHParameterSpec(p, g);
            KeyPairGenerator clientKeyPairGen = KeyPairGenerator.getInstance("DH");
            clientKeyPairGen.initialize(dhSpecClient);
            KeyPair clientKeyPair = clientKeyPairGen.generateKeyPair();
            BigInteger gymodp = ((DHPublicKey) clientKeyPair.getPublic()).getY();
            long finalTimeGy = System.nanoTime();
            out.writeObject(gymodp);

            // Calcular llave compartida
            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(clientKeyPair.getPrivate());
            DHPublicKeySpec dhPubKeySpec = new DHPublicKeySpec(gxmodp, p, g);
            PublicKey serverPublicKey = KeyFactory.getInstance("DH").generatePublic(dhPubKeySpec);
            keyAgreement.doPhase(serverPublicKey, true);
            byte[] clientSecret = keyAgreement.generateSecret();
            SecretKey clientAesKey = new SecretKeySpec(clientSecret, 0, 16, "AES");

            // Generar el digest SHA-512 de la llave maestra
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] digest = sha512.digest(clientAesKey.getEncoded());

            // Dividir el digest en dos partes de 256 bits (32 bytes cada una)
            byte[] encryptionKey = new byte[32]; // para AES
            byte[] hmacKey = new byte[32]; // para HMAC

            System.arraycopy(digest, 0, encryptionKey, 0, 32); // Copiar los primeros 32 bytes
            System.arraycopy(digest, 32, hmacKey, 0, 32); // Copiar los últimos 32 bytes

            // Crear las claves SecretKey para AES y HMAC
            SecretKey aesKey = new SecretKeySpec(encryptionKey, "AES");
            SecretKey hmacSha256Key = new SecretKeySpec(hmacKey, "HmacSHA256");
            
            

            // Esperar la señal "CONTINUAR"
            if ("CONTINUAR".equals(in.readObject())) {
                System.out.println("CONTINUAR recibido");

                // Enviar credenciales cifradas
                String credentials = "usuario:contrasena";
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                SecretKeySpec keySpec = new SecretKeySpec(aesKey.getEncoded(), "AES");
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
                byte[] encryptedCredentials = cipher.doFinal(credentials.getBytes());
                out.writeObject(encryptedCredentials);
                System.out.println("Credenciales enviadas exitosamente.");

                if("OK".equals(in.readObject())) {
                    System.out.println("OK recibido");

                    // Enviar consulta cifrada y su HMAC
                    long startTimeConsulta = System.nanoTime();
                    String consulta = "Consulta de saldo";
                    byte[] consultabytes = consulta.getBytes();
                    cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
                    byte[] encryptedQuery = cipher.doFinal(consultabytes);
                    long finalTimeConsulta = System.nanoTime();
                    out.writeObject(encryptedQuery);

                    long startTimeHMAC = System.nanoTime();
                    Mac mac = Mac.getInstance("HmacSHA256");
                    mac.init(hmacSha256Key);
                    byte[] hmacConsulta = mac.doFinal(consulta.getBytes());
                    long finalTimeHMAC = System.nanoTime();
                    out.writeObject(hmacConsulta);
                    System.out.println("Consulta y HMAC enviados al servidor.");

                    // Recibir y verificar la respuesta cifrada y su HMAC
                    byte[] encryptedResponse = (byte[]) in.readObject();
                    byte[] hmacResponse = (byte[]) in.readObject();
                    cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
                    byte[] decryptedResponse = cipher.doFinal(encryptedResponse);
                    System.out.println("Respuesta recibida y descifrada: " + new String(decryptedResponse));

                    mac.init(hmacSha256Key);
                    byte[] calculatedHmac = mac.doFinal(decryptedResponse);

                    if (MessageDigest.isEqual(hmacResponse, calculatedHmac)) {
                        System.out.println("HMAC verificado con éxito.");
                    } else {
                        System.out.println("Error de verificación HMAC.");
                    }

                    long tiempoFirma = finalTimeFirma-startTimeFirma;
                    long tiempoGy = finalTimeGy-startTimeGy;
                    long tiempoConsulta = finalTimeConsulta-startTimeConsulta;
                    long tiempoAutenticacion = finalTimeHMAC-startTimeHMAC;
                    System.out.println("Tiempo de verificar firma: "+tiempoFirma);
                    System.out.println("Tiempo de calcular gy: "+tiempoGy);
                    System.out.println("Tiempo de consulta: "+tiempoConsulta);
                    System.out.println("Tiempo de HMAC: "+tiempoAutenticacion);
                }

                
            }

        } catch (Exception e) {
            System.out.println("Exception: " + e.getMessage());
        } finally {
            try {
                if (socket != null) socket.close();
            } catch (IOException e) {
                System.out.println("Error al cerrar el socket: " + e.getMessage());
            }
        }
    }
}



