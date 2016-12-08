
import java.util.Random;
import java.util.Scanner;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.io.FileInputStream;

public class Merchant {

    private static Key publicKey;	//object for the public key
    private static Key privateKey;	//object for the private key

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, Exception {
        Scanner keyboard = new Scanner(System.in);
        Scanner fin = null;
        boolean cont = true;
        int option;
        String moFile = "";
        File keyFile = new File("./Merchant/public.key");
        if (!keyFile.exists()) {
            setKeys();
        }
        printMenu();
        System.out.println("Merchant Program");
        System.out.print("Select an option: ");
        option = keyboard.nextInt();
            switch (option) {
                case 1: //Select Money Order file
                    System.out.print("Enter the name of the money order file:");
                    moFile = keyboard.next();
                    File file = new File(moFile);
                    if (!file.exists()) {
                        file.createNewFile();
                    }
                    fin = new Scanner(new FileReader(moFile));
                    break;

                case 2:	//Verify bank Signature
                    String datafile = "./Digital-Cash/test.txt";
                    //SignatureTest.verify(datafile, pubk, "SHAwithDSA", sigbytes);
                    //System.out.println("Signature Verification Result = " + result);
                    break;

                case 3:	//Generate random integer to customer to determine halves of ID string to unblind		

                    Random rand = new Random(42000);
                    int selectorString = rand.nextInt() * 10;
                    String selectorStringBin = Integer.toBinaryString(selectorString);
                    BufferedWriter bw = new BufferedWriter(new FileWriter(("./Digital-Cash/SelectorString/" + moFile), true));
                    bw.write(selectorStringBin);
                    bw.close();
                    break;

                case 4:	//Output the signed, unblinded money order with ID halves for the bank
                    break;
                case 5:
                    break;

                case 6:
                    cont = false;
                    break;
            }
    }
    //Method to generate RSA key pair
    //In practice a higher key length than 2048 would increase confidentiality of the money orders, 
    //however it would be time consuming to decrypt in use.

    private static void setKeys() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        //Create a private and public RSA key pair with a key size of 2048 bits
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.genKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();

        //Retrieve modulus and exponent of keys to store the keys for reference
        KeyFactory keyFact = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pub = keyFact.getKeySpec(keyPair.getPublic(),
                RSAPublicKeySpec.class);	//RSA public key object
        RSAPrivateKeySpec priv = keyFact.getKeySpec(keyPair.getPrivate(),
                RSAPrivateKeySpec.class); //RSA private key object

        //Sends the file name, modulus, and exponents to file for future storage,
        //such that the Merchant can run the program multiple times once a key pair has been generated
        writeKey("./Merchant/public.key", pub.getModulus(), pub.getPublicExponent());
        writeKeyPublic("./Digital-Cash/Merchant/public.key", pub.getModulus(), pub.getPublicExponent());
        writeKey("./Merchant/private.key", priv.getModulus(), priv.getPrivateExponent());
    }
    //Writes private and public key to file for future reference.
    //Modulus and Exponent values will be used to retrieve the keys,
    //It is assumed that the key values are stored securely

    public static void writeKey(String fileName, BigInteger modulus, BigInteger exponent) throws IOException {
        ObjectOutputStream privateDB = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fileName)));
        ObjectOutputStream publicDB = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream("D:\\Sindhu\\Education\\Crypto\\Digital-Cash\\PublicKeyDB\\MerchantPublic")));
        try {
            privateDB.writeObject(modulus);
            privateDB.writeObject(exponent);
        } catch (Exception e) {
            throw new IOException("File output error", e);
        } finally {
            privateDB.close();
            publicDB.close();
        }
    }
    //Similar method to writeKey, but the public key is written to a public database instead

    public static void writeKeyPublic(String fileName, BigInteger modulus, BigInteger exponent) throws IOException {
        try (ObjectOutputStream publicDB = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream("D:\\Sindhu\\Education\\Crypto\\Digital-Cash\\PublicKeyDB\\MerchantPublic")))) {
            publicDB.writeObject(modulus);
            publicDB.writeObject(exponent);
        } catch (Exception e) {
            throw new IOException("File output error", e);
        }
    }

    PublicKey readPublicKey(String keyFileName) throws IOException {
        InputStream in = new FileInputStream(keyFileName);
        try (ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(in))) {
            BigInteger mod = (BigInteger) oin.readObject();
            BigInteger exp = (BigInteger) oin.readObject();
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(mod, exp);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            PublicKey pubKey = fact.generatePublic(keySpec);
            return pubKey;
        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Error encountered", e);
        }
    }

    PrivateKey readPrivateKey(String keyFileName) throws IOException {
        InputStream in = new FileInputStream(keyFileName);
        try (ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(in))) {
            BigInteger mod = (BigInteger) oin.readObject();
            BigInteger exp = (BigInteger) oin.readObject();
            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(mod, exp);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            PrivateKey privKey = fact.generatePrivate(keySpec);
            return privKey;
        } catch (Exception e) {
            throw new RuntimeException("Error encountered", e);
        }
    }

   

    public static void printMenu() {
        System.out.println("1: Select Money Order file");
        System.out.println("2: Verify Bank signature");
        System.out.println("3: Generate random bit string");
        System.out.println("4: Unblind ID strings ");
        System.out.println("5: Output Money Order for Bank");
        System.out.println("6: End program");

    }
}
