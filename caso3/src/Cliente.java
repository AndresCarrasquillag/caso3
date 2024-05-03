import java.net.Socket;
import java.security.PublicKey;

public class Cliente {
    private Socket socket;
    private PublicKey publicKey;
    private long p;
    private long g;
    private long x;



    public Cliente(PublicKey publicKey, long p, long g, long x) {
        this.publicKey = publicKey;
        this.p = p;
        this.g = g;
        this.x = x;
    }
}
