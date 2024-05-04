import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import javax.crypto.spec.DHParameterSpec;

public class Servidor {
    public static final int PUERTO = 3400;
    private static PrivateKey privateKey;
    public static PublicKey publicKey;
    
    public static void main(String args[]) throws IOException, NoSuchAlgorithmException {
        ServerSocket ss = null;
        boolean continuar = true;
        
        try {
            ss = new ServerSocket(PUERTO);
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(-1);
        }

        while (continuar) {
            privateKey = Main.GenerarLlavesAsimétricas().getPrivate();
            publicKey = Main.GenerarLlavesAsimétricas().getPublic();
            Socket socket = ss.accept();
            System.out.println("Servidor escuchando en el puerto " + PUERTO);
            try {
                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream inputStream = new ObjectInputStream(socket.getInputStream());
                out.writeObject(publicKey);
                // PUNTO 2
                String retoString = (String)inputStream.readObject();
                System.out.println("h");
                BigInteger reto = new BigInteger(retoString);
                Signature firma = Signature.getInstance("SHA256withRSA");
                firma.initSign(privateKey);
                byte[] retoBytes = reto.toByteArray();
                firma.update(retoBytes);
                System.out.println(retoBytes);
                byte[] firm = firma.sign();
                out.writeObject(firm);

                // PUNTO 3
                //out.writeObject(CifradoAsimetrico.cifrar(privateKey, "RSA/ECB/PKCS1Padding", reto.toByteArray()));

                //PUNTO 5 server
                String resp = (String) inputStream.readObject();
                System.out.println(resp);

                /// PUNTO 6
                BigInteger[] params = DiffieHallman.generarParams();
                BigInteger g = params[0];
                BigInteger p = params[1];
                BigInteger gxmodp = params[2];

                // PUNTO 7
                out.writeObject(g);
                out.writeObject(p);
                out.writeObject(gxmodp);
                out.writeObject(CifradoAsimetrico.cifrar(privateKey, "RSA/ECB/PKCS1Padding", g.toByteArray()));
                out.writeObject(CifradoAsimetrico.cifrar(privateKey, "RSA/ECB/PKCS1Padding", p.toByteArray()));
                out.writeObject(CifradoAsimetrico.cifrar(privateKey, "RSA/ECB/PKCS1Padding", gxmodp.toByteArray()));

                
            } catch (Exception e) {
                // TODO: handle exception
            }
        }
    }
    
    public Servidor(PrivateKey privateKey, long p, long g, long x) {
        this.privateKey = privateKey;
    }
};
