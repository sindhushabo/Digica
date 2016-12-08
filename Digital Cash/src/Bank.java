
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.util.Scanner;
import java.io.FileInputStream;

public class Bank {

    static PublicKey publicKey;
    static PrivateKey privateKey;

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, InvalidKeySpecException, IOException, Exception {
        Scanner keyIn = new Scanner(System.in);
        String amount = null;
        int option;
        String dir = "";
        int blindMO = 0;
        File keyFile = new File("./Bank/public.key");
        if (!keyFile.exists()) {
            setKeys();
        }
        SecureRandom secRand = new SecureRandom();
        System.out.println("Do you want to start? (Y/N)");
        char choice = keyIn.next().charAt(0);
        System.out.println("Bank program:");
        while (choice == 'y' || choice == 'Y') {
            printMenu();
            option = keyIn.nextInt();
            switch (option) {	//Menu switch statement

                case 1: //Generate random number to indicate which money order not to unblind
                    blindMO = secRand.nextInt(10);
                    PrintWriter blindFile = new PrintWriter(new FileOutputStream("./Blind/blindFile.txt"));
                    blindFile.print(blindMO);
                    blindFile.close();                    //writeBlindInt(blindFile, blindMO);

                    break;

                case 2:	//Check unblinded Money orders for inconsistent amounts
                    boolean cheat = false;
                    boolean unique = true;
                    String tmp = null;
                    for (int i = 0; i < 4; i++) {
                        Customer.unblind(i);
                    }
                    for (int i = 0; i < 4; i++) {
                        File fileName = new File("./MO-unblinded2/" + "MO-" + i);
                        try {
                            Scanner fin = new Scanner(new FileReader(fileName));
                            String UID = fin.nextLine();
                            if (UID == tmp) {
                                System.out.println("Duplicate UID detected");
                            }
                            tmp = UID;
                            if (amount == null) {
                                amount = fin.nextLine();
                                continue;
                            }
                            String amountTemp = fin.nextLine();
                            if (amountTemp != amount) {
                                cheat = true;
                                break;
                            }

                        } catch (FileNotFoundException e) {
                        }
                    }
                    
                    if (cheat == true) {
                        System.out.println("Money Order amounts inconsistent!");
                		BankKeysGenration();	
                        bankSignSignature("./MO-unsigned/MO-4");
                        System.exit(0);
                    } else {
                        System.out.println("Money Order amounts consistent");
                    }
                    break;

                case 4:
                	bankVerifySignSignature("./MO-unsigned/MO-4");
                    break;

                default:
                    System.out.println("Invalid Option");
                    break;
            }
            System.out.println("Do you want to continue? (Y/N)");
            choice = keyIn.next().charAt(0);
        }

    }

    //Prints menu block
    public static void printMenu() {
        System.out.print("\nChoose an option: ");
        System.out.println("1: Generate random integer for customer");
        System.out.println("2: Verify the unblinded Money Orders");
        System.out.println("3: Sign blind Money Order");
        System.out.println("4: Check if Money order ID has been used");
    }

    //Method to write the random int to file for the customer not to reveal
    private static void writeBlindInt(File fout, int blind) {
        try {
            try (FileOutputStream blindFile = new FileOutputStream(fout)) {
                blindFile.write(blind);
            }
        } catch (IOException e) {
            // TODO Auto-generated catch block
        }
    }
    
    
    public static void BankKeysGenration() throws IOException {
		ObjectOutputStream pubKeys = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream("./BankSignature/pubKeys")));
		ObjectOutputStream privKeys = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream("./BankSignature/privKeys")));
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
		    kpg.initialize(512); // 512 is the keysize.
		    KeyPair kp = kpg.generateKeyPair();
		    PublicKey pubk = kp.getPublic();
		    PrivateKey prvk = kp.getPrivate();
		    privKeys.writeObject(prvk);
			pubKeys.writeObject(pubk);
		} catch (Exception e) {
			throw new IOException("File output error", e);
		} finally {
			privKeys.close();
			pubKeys.close();
		}
	}
    
    private static void bankSignSignature(String datafile){
    	 // Generate a key-pair
        
		try {
			PrintWriter fout = new PrintWriter(new FileOutputStream("./BankSignature/sign"));
			InputStream in = new FileInputStream("./BankSignature/privKeys");
			ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(in)) ;
			PrivateKey prvk = (PrivateKey) oin.readObject();
	        byte[] sigbytes = SignatureTest.sign(datafile, prvk, "SHAwithDSA");
	        System.out.println("Signature  = " + sigbytes);
	        fout.print(sigbytes);
	    	fout.close();
	        //boolean result = verify(datafile, pubk, "SHAwithDSA", sigbytes);
	        //System.out.println("Signature Verification Result = " + result);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
    }
    
    private static void bankVerifySignSignature( String datafile){
   	 // Generate a key-pair
       KeyPairGenerator kpg;
		try {
			InputStream in = new FileInputStream("./BankSignature/pubKeys");
			ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(in)) ;
			PublicKey pubk = (PublicKey) oin.readObject();
			//ObjectInputStream oin2 = new ObjectInputStream(new BufferedInputStream(in2)) ;
			Scanner fin = null;
			fin = new Scanner(new FileInputStream("./BankSignature/sign"));
			byte[] sigbytes=  new byte[]{};
			int j=0;
			while(fin.hasNextByte()){
				sigbytes[j]=fin.nextByte();
				j++;
			}
			System.out.println("sigbytes----"+sigbytes);
			boolean result = SignatureTest.verify(datafile, pubk, "SHAwithDSA", sigbytes);
	        System.out.println("Signature Verification Result = " + result);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
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
        writeKey("./Bank/public.key", pub.getModulus(), pub.getPublicExponent());
        writeKeyPublic("./Bank/public.key", pub.getModulus(), pub.getPublicExponent());
        writeKey("./Bank/private.key", priv.getModulus(), priv.getPrivateExponent());
    }

    //Writes private and public key to file for future reference.
    //Modulus and Exponent values will be used to retrieve the keys,
    //It is assumed that the key values are stored securely
    public static void writeKey(String fileName, BigInteger modulus, BigInteger exponent) throws IOException {
        ObjectOutputStream privateDB = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fileName)));
        ObjectOutputStream publicDB = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream("./PublicKeyDB/BankPublic")));
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
        try (ObjectOutputStream publicDB = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream("./PublicKeyDB/BankPublic")))) {
            publicDB.writeObject(modulus);
            publicDB.writeObject(exponent);
        } catch (Exception e) {
            throw new IOException("File output error", e);
        }
    }

    //Reads a previously stored public key
    PublicKey readPublicKey(String keyFileName) throws IOException {
        InputStream in = new FileInputStream(keyFileName);
        try (ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(in))) {
            BigInteger mod = (BigInteger) oin.readObject();
            BigInteger exp = (BigInteger) oin.readObject();
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(mod, exp);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            PublicKey pubKey = fact.generatePublic(keySpec);
            return pubKey;
        } catch (Exception e) {
            throw new RuntimeException("Error encountered", e);
        }
    }

    //Reads a previously stored private key
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
    
    
}
