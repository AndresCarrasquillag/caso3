import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;

import javax.crypto.spec.DHParameterSpec;

public class Servidor {
    public static final int PUERTO = 3400;
    private static PrivateKey privateKey;
    
    public static void main(String args[]) throws IOException {
        ServerSocket ss = null;
        boolean continuar = true;
        
        try {
            ss = new ServerSocket(PUERTO);
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(-1);
        }

        while (continuar) {
            Socket socket = ss.accept();
            System.out.println("Servidor escuchando en el puerto " + PUERTO);
            try {
                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream inputStream = new ObjectInputStream(socket.getInputStream());

                // PUNTO 2
                BigInteger reto = (BigInteger) inputStream.readObject();
                System.out.println(reto);
                // PUNTO 3
                out.writeObject(CifradoAsimetrico.cifrar(privateKey, "AES/CBC/PKCS5Padding", reto.toString()));
                /// PUNTO 6
                BigInteger[] params = DiffieHallman.generarParams();
                BigInteger g = params[0];
                BigInteger p = params[1];
                BigInteger gxmodp = params[2];
                // PUNTO 7
                out.writeObject(g);
                out.writeObject(p);
                out.writeObject(gxmodp);
                out.writeObject(CifradoAsimetrico.cifrar(privateKey, "AES/CBC/PKCS5Padding", g.toString()));
                out.writeObject(CifradoAsimetrico.cifrar(privateKey, "AES/CBC/PKCS5Padding", p.toString()));
                out.writeObject(CifradoAsimetrico.cifrar(privateKey, "AES/CBC/PKCS5Padding", gxmodp.toString()));

                
            } catch (Exception e) {
                // TODO: handle exception
            }
        }
    }
    
    public Servidor(PrivateKey privateKey, long p, long g, long x) {
        this.privateKey = privateKey;
    }
};
