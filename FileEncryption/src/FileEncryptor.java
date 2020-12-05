import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static java.util.Base64.getMimeEncoder;

/**
 *
 * @author Erik Costlow
 */
public class FileEncryptor {
    private static final Logger LOG = Logger.getLogger(FileEncryptor.class.getSimpleName());

    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, InvalidKeySpecException {
        PBEKeySpec pbeKeySpec;
        PBEParameterSpec pbeParamSpec;
        SecretKeyFactory keyFac;

        //This snippet is literally copied from SymmetrixExample
        SecureRandom sr = new SecureRandom();
        byte[] key = new byte[16];
        sr.nextBytes(key); // 128 bit key
        byte[] initVector = new byte[16];
        sr.nextBytes(initVector); // 16 bytes IV
        //System.out.println("Random key=" + Util.bytesToHex(key));
        //System.out.println("initVector=" + Util.bytesToHex(initVector));
        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec skeySpec;

        //This is my relatively poor attempt at Part 3 of the assignment
        //It gets the password and I thought I could replace skeySpec with pbeKet but that failed.
        /*char[] password = args[1].toCharArray();
        pbeKeySpec = new PBEKeySpec(password);
        keyFac = SecretKeyFactory.getInstance(CIPHER);
        SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);*/

        Cipher cipher = Cipher.getInstance(CIPHER);

        //Gives user the choice between encryption and decryption
        if (args[0].equals("enc")) {

            key = Base64.getDecoder().decode(args[1]);
            skeySpec = new SecretKeySpec(key,ALGORITHM);

            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            final Path base = Paths.get(args[3]); //New base file using the second argument

            try (InputStream fin = FileEncryptor.class.getResourceAsStream(args[2]); //Name of the file to encrypt
                 OutputStream fout = Files.newOutputStream(base);
                 CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
                 }) {
                fout.write(initVector);//Stores the IV in the file
                final byte[] bytes = new byte[1024];
                for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
                    cipherOut.write(bytes, 0, length);
                }

                System.out.println("Secret key is " + Base64.getEncoder().encodeToString(key));//Base64 encoded key to use in decryption
                System.out.println("IV is " + Base64.getEncoder().encodeToString(initVector));//Base64 encoded iv to use in decryption
            } catch (IOException e) {
                LOG.log(Level.INFO, "Unable to encrypt", e);
            }
        }
        else if(args[0].equals("dec")) {
            //Decoded base64 key to recreate the same cipher
            key = Base64.getDecoder().decode(args[1]);
            skeySpec = new SecretKeySpec(key,ALGORITHM);

            final Path base = Paths.get(args[3]);

            //First try brings out the IV stored in the file, second try is the decryption
            try(FileInputStream fileIn = new FileInputStream(args[2])) {
                byte[] fileIV = new byte[16];
                fileIn.read(fileIV);//This gets rid of it in the file
                cipher.init(Cipher.DECRYPT_MODE, skeySpec, new IvParameterSpec(fileIV));

                try (CipherInputStream decryptStream = new CipherInputStream(fileIn, cipher);
                     OutputStream decryptedOut = Files.newOutputStream(base)) {
                    final byte[] bytes = new byte[1024];
                    for (int length = decryptStream.read(bytes); length != -1; length = decryptStream.read(bytes)) {
                        decryptedOut.write(bytes, 0, length);
                    }
                }
            } catch (IOException ex) {
                Logger.getLogger(FileEncryptor.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
            }

            LOG.info("Decryption complete, open " + base);
        }
    }
}