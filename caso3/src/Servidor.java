import java.security.PrivateKey;

public class Servidor {
    private PrivateKey privateKey;
    private long p;
    private long g;
    private long x;

    
    public Servidor(PrivateKey privateKey, long p, long g, long x) {
        this.privateKey = privateKey;
        this.p = p;
        this.g = g;
        this.x = x;
    }
}
