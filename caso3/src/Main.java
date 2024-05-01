import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Main {

    private static PublicKey publicK;
    private static PrivateKey privateK;
    public static void main(String[] args) throws Exception {
        KeyPair keyPair = GenerarLlavesAsimétricas();
        publicK = keyPair.getPublic();
        privateK = keyPair.getPrivate();
        //¿En qué momento se crean servidores y clientes delegados?
        //Crear Servidor(es) y Cliente(s)
        System.out.println("Hello, Worldaaaasaa!");


    }

	public static KeyPair GenerarLlavesAsimétricas() throws NoSuchAlgorithmException {
			
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(1024);
			KeyPair keyPair = generator.generateKeyPair();

			//PublicKey publica = keyPair.getPublic();
			//PrivateKey privada = keyPair.getPrivate();
			return keyPair;
		}
}
