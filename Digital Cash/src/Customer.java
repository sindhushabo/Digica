/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.

/**
 *
 * @author Sindhu Pranay
 */


import java.util.*;
import java.io.*;
import java.nio.*;
import java.math.*;
import java.security.*;
import java.security.spec.*;
import java.math.BigInteger;

import javax.crypto.*;


public class Customer {
	private static Key publicKey; // object for the public key
	private static Key privateKey; // object for the private key

	public static void main(String[] args) {
		Scanner kb = new Scanner(System.in);
		Random random = new Random();
		PrintWriter fout = null;
		int mod = 0;
		int k1 = 0;
		try {
			fout = new PrintWriter(new FileOutputStream("./PublicKeyDB/PublicModulus"));
			mod = Math.abs(random.nextInt());
			fout.print(mod);
			fout.close();
			fout = new PrintWriter(new FileOutputStream("./Customer/k"));
			k1 = random.nextInt((mod - 1) + 1) + 1; // mod > k1 > 1
			fout.print(k1);
			fout.close();
		}catch(FileNotFoundException e) {
		}
		//Prompt user for number of orders and amount of money
		System.out.print("Number of orders: ");
		int numOrders = kb.nextInt();
		System.out.print("Amount of money: ");
		double amtMoney = kb.nextDouble();
		int pubInt = 0;
		try {
			setKeys();
		}catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
		}try {
			PublicKey pub = readPublicKey("./Customer/public.key");
			byte[] pubBytes = pub.getEncoded();
			pubInt = ByteBuffer.wrap(pubBytes).getInt();
		}catch(IOException e){
		}
		
		//Creating random numbers and identity strings (Secret splitting)
		for(int k=0;k<numOrders;k++) {
			long ident = Math.abs(random.nextLong());
			int[][] identStrings = new int[numOrders][numOrders];
			int[][] randBits = new int[numOrders][numOrders];
			int[][] left = new int[numOrders][numOrders];
			int[][] right = new int[numOrders][numOrders];

			/*for (int i = 0; i < numOrders; i++)
				for (int j = 0; j < numOrders; j++) {
					randBits[i][j] = randomBits();
				}
			for (int i = 0; i < numOrders; i++)
				for (int j = 0; j < numOrders; j++) {
					identStrings[i][j] = iStringGen(numOrders, amtMoney, randBits[i][j]);
				}

			for (int i = 0; i < numOrders; i++)
				for (int j = 0; j < numOrders; j++) {
					left[i][j] = encrypt(randBits[i][j]);
				}
			for (int i = 0; i < numOrders; i++)
				for (int j = 0; j < numOrders; j++) {
					right[i][j] = encrypt(identStrings[i][j]);
				}

			for (int i = 0; i < numOrders; i++)
				for (int j = 0; j < numOrders; j++) {
					identStrings[i][j] = iStringGen(numOrders, amtMoney, randBits[i][j]);
				}*/
			try {
				fout = new PrintWriter(new FileOutputStream("./MO-unblinded/MO-"+k));
				fout.println(ident); //Anonymous moneyorders with random uniqu strings
				fout.println(amtMoney);//money 
				/*int n = 1;
				for (int i = 0; i < numOrders; i++)
					for (int j = 0; j < numOrders; j++) {
						fout.println(left[i][j] + "," + right[i][j]);
						n++;
					}*/

			} catch (FileNotFoundException e) {
			} finally {
				fout.close();
			}
		}
		blind(numOrders);
		//unblind(numOrders);
		kb.close();
	}

	public static int iStringGen(int x, double y, int z) {
		int s = 0;
		s = z ^ (int) y;
		return s;
	}

	public static int randomBits() {
		Random random = new Random();
		byte[] ra = new byte[30];
		random.nextBytes(ra);
		int z = ByteBuffer.wrap(ra).getInt();
		return z;
	}

	// Method to generate RSA key pair
	// In practice a higher key length than 2048 would increase confidentiality
	// of the money orders,
	// however it would be time consuming to decrypt in use.
	private static void setKeys() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
		// Create a private and public RSA key pair with a key size of 2048 bits
                SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
		keyPairGen.initialize(1024,random);
		KeyPair keyPair = keyPairGen.genKeyPair();
		publicKey = keyPair.getPublic();
		privateKey = keyPair.getPrivate();
                
		// Retrieve modulus and exponent of keys to store the keys for reference
		KeyFactory keyFact = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec pub = keyFact.getKeySpec(keyPair.getPublic(), RSAPublicKeySpec.class); // RSA public key object
		RSAPrivateKeySpec priv = keyFact.getKeySpec(keyPair.getPrivate(), RSAPrivateKeySpec.class); // RSA private key object
		RSAPublicKeySpec blindPub = keyFact.getKeySpec(keyPair.getPublic(), RSAPublicKeySpec.class); // RSA public key object for blinding
		RSAPrivateKeySpec blindPriv = keyFact.getKeySpec(keyPair.getPrivate(), RSAPrivateKeySpec.class); // RSA private key object for blinding
		// Sends the file name, modulus, and exponents to file for future
		// storage,
		// such that the Merchant can run the program multiple times once a key
		// pair has been generated
		writeKey("./Customer/public.key", pub.getModulus(), pub.getPublicExponent());
		writeKeyPublic("./Customer/public.key", pub.getModulus(), pub.getPublicExponent());
		writeKey("./Customer/private.key", priv.getModulus(), priv.getPrivateExponent());

		writeKey("./Customer/blindPublic.key", blindPub.getModulus(), blindPub.getPublicExponent());
		writeKeyPublic("./Customer/blindPublic.key", blindPub.getModulus(), blindPub.getPublicExponent());
		writeKey("./Customer/blindPrivate.key", blindPriv.getModulus(), blindPriv.getPrivateExponent());
	}

	// Writes private and public key to file for future reference.
	// Modulus and Exponent values will be used to retrieve the keys,
	// It is assumed that the key values are stored securely
	public static void writeKey(String fileName, BigInteger modulus, BigInteger exponent) throws IOException {
		ObjectOutputStream privateDB = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fileName)));
		ObjectOutputStream publicDB = new ObjectOutputStream(
				new BufferedOutputStream(new FileOutputStream("./PublicKeyDB/CustomerPublic")));
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

	// Similar method to writeKey, but the public key is written to a public
	// database instead
	public static void writeKeyPublic(String fileName, BigInteger modulus, BigInteger exponent) throws IOException {
		try (ObjectOutputStream publicDB = new ObjectOutputStream(
                        new BufferedOutputStream(new FileOutputStream("./PublicKeyDB/CustomerPublic")))) {
			publicDB.writeObject(modulus);
			publicDB.writeObject(exponent);
		} catch (Exception e) {
			throw new IOException("File output error", e);
		}
	}

	static PublicKey readPublicKey(String keyFileName) throws IOException {
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

	static PrivateKey readPrivateKey(String keyFileName) throws IOException {
		InputStream in = new FileInputStream(keyFileName);
		try (ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(in))) {
			BigInteger mod = (BigInteger) oin.readObject();
			BigInteger exp = (BigInteger) oin.readObject();
			RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(mod, exp);
			KeyFactory fact = KeyFactory.getInstance("RSA");
			PrivateKey privKey = fact.generatePrivate(keySpec);
			return privKey;
		} catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new RuntimeException("Error encountered", e);
		}
	}
	//Source: https://javadigest.wordpress.com/2012/08/26/rsa-encryption-example/
	public static int encrypt(int text) {
		byte[] cipherText = null;
		try {
			PublicKey key = readPublicKey("./Customer/public.key");
			// get an RSA cipher object and print the provider
			final Cipher cipher = Cipher.getInstance("RSA");
			// encrypt the plain text using the public key
			cipher.init(Cipher.ENCRYPT_MODE, key);
			cipherText = cipher.doFinal(ByteBuffer.allocate(4).putInt(text).array());
		} catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
		}
		int cipherInt = ByteBuffer.wrap(cipherText).getInt();
		return cipherInt;
	}
	public static int decrypt(int text) {

		byte[] decryptedText = null;
		try {
			PrivateKey key = readPrivateKey("./Customer/private.key");
			// get an RSA cipher object and print the provider
			final Cipher cipher = Cipher.getInstance("RSA");

			// decrypt the text using the private key
			cipher.init(Cipher.DECRYPT_MODE, key);
			decryptedText = cipher.doFinal(ByteBuffer.allocate(100).putInt(text).array());

		} catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
		}
		int decryptedInt = ByteBuffer.wrap(decryptedText).getInt();
		return decryptedInt;
	}
	
	static public void blind(int numOrders){
		RSA rsa = new RSA(1024);
		Scanner fin = null;
		PrintWriter fout = null;
		BufferedWriter publicDB=null;
		try{
		for(int i=0; i<numOrders; i++){
			fin = new Scanner(new FileInputStream("./MO-unblinded/MO-"+i));
			publicDB = new BufferedWriter(
	                    new FileWriter("./MO-unsigned/MO-"+i));
			
			while(fin.hasNextLine()){
				BigInteger plaintext = new BigInteger(fin.nextLine().getBytes("ISO-8859-1"));
			    BigInteger ciphertext = rsa.encrypt(plaintext);
				publicDB.write(ciphertext.toString());
				publicDB.write("\n");
			}
			fin.close();
			publicDB.close();
			
		}
		}catch(Exception e){
			System.out.println("Exception "+e);
		}
		
		
	}
	/**
	 * Unblinds a money order matching given orderNum
	 * @param orderNum
     */
	public static void unblind(int numOrders) {
		
		RSA rsa = new RSA(1024);
		Scanner fin = null;
		BufferedWriter publicDB=null;
		try{
		for(int i=0; i<numOrders; i++){
			fin = new Scanner(new FileInputStream("./MO-unsigned/MO-"+i));
			 
			 publicDB = new BufferedWriter(
	                    new FileWriter("./MO-unblinded2/MO-"+i));
			
			while(fin.hasNextLine()){
				
			    String cipher=fin.nextLine().toString();
			    String plaintext3 = rsa.decrypt(cipher);
			    //System.out.println("plaintext3-------"+plaintext3);
				publicDB.write(plaintext3.toString());
				publicDB.write("\n");
			}
			fin.close();
			publicDB.close();
			
		}
		}catch(Exception e){
			System.out.println("Exception "+e);
		}
		
		
	}
}
