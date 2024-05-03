import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;

import javax.crypto.spec.DHParameterSpec;

public class Servidor {
    public static final int PUERTO = 3400;
    private PrivateKey privateKey;
    private long p;
    private long g;
    private long x;
    
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
            try {

                /// PUNTO 6
                BigInteger[] params = DiffieHallman.generarParams();
                BigInteger g = params[0];
                BigInteger p = params[1];
                BigInteger gxmodp = params[2];
                
                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                out.writeObject(g);
                out.writeObject(p);
                out.writeObject(gxmodp);
                
            } catch (Exception e) {
                // TODO: handle exception
            }
        }
    }
    
    public Servidor(PrivateKey privateKey, long p, long g, long x) {
        this.privateKey = privateKey;
        this.p = p;
        this.g = g;
        this.x = x;
    }
};
