import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

public class DiffieHallman {

    public static Object[] generarParams() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
        keyPairGen.initialize(1024);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        DHPublicKey publicKey = (DHPublicKey) keyPair.getPublic();
        DHParameterSpec params = publicKey.getParams();

        BigInteger g = params.getG();
        BigInteger p = params.getP();
        BigInteger gxmodp = publicKey.getY();
        Object[] parametros = {g, p, gxmodp, keyPair};

        return parametros;
    }

}
