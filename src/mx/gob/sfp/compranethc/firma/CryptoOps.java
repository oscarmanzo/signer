package mx.gob.sfp.compranethc.firma;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Clase CryptoOps
 * Componente para codificación de datos. Contiene métodos para
 * la codificación de decodificación de datos y llaves.
 * 
 * User: serch
 */
public class CryptoOps {

	/**
	 * Genera una llave simétrica basada en el algoritmo AES.
	 * 
	 * @return llave simétrica
	 */
	public static SecretKey getAESKey() {
		KeyGenerator kgen;
		try {
			kgen = KeyGenerator.getInstance("AES");
			kgen.init(256, new SecureRandom(Long.toString(System.currentTimeMillis()).getBytes()));
			SecretKey key = kgen.generateKey();

			try {
				Cipher cipher = Cipher.getInstance("AES");
				cipher.init(Cipher.ENCRYPT_MODE, key);
			} catch (InvalidKeyException e) {
				e.printStackTrace();
				// Client suport only 128 bit Key
				kgen = KeyGenerator.getInstance("AES");
				kgen.init(128, new SecureRandom(Long.toString(
						System.currentTimeMillis()).getBytes()));
				key = kgen.generateKey();
			} catch (NoSuchPaddingException e) {
				e.printStackTrace();
				// unrecoverable Error... Nothing to do
			}

			return key;

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			// TODO Reportar error de algoritmo
			return null;
		}

	}

	/**
	 * Codifica los datos de entrada mediante la llave simétrica proporcionada
	 * 
	 * @param in datos
	 * @param key llave simétrica
	 * 
	 * @return datos codificados
	 */
	public static byte[] encodeData(byte[] in, SecretKey key) {
		try {
			SecretKeySpec skeySpec = new SecretKeySpec(key.getEncoded(), "AES");
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
			return cipher.doFinal(in);
		} catch (GeneralSecurityException e) { // If error we just return a null
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Decodifica los datos de entrada mediante la llave simétrica proporcionada
	 * 
	 * @param in datos codificados
	 * @param key llave simétrica
	 * 
	 * @return datos planos
	 */
	public static byte[] decodeData(byte[] in, SecretKey key) {
		try {
			SecretKeySpec skeySpec = new SecretKeySpec(key.getEncoded(), "AES");
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.DECRYPT_MODE, skeySpec);
			return cipher.doFinal(in);
		} catch (GeneralSecurityException e) { // If error we just return a null
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Codifica una llave simétrica mediante la llave publica de la autoridad certificadora,
	 * aplicando una firma digital mediante la llave privada del propietario
	 * 
	 * @param key llave simétrica
	 * @param myKey llave privada del propietario
	 * @param CAKey llave publica de la autoridad certificadora
	 * 
	 * @return llave codificada
	 */
	public static byte[] packKey(SecretKey key, RSAPrivateKey myKey, RSAPublicKey CAKey) {
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, CAKey);
			byte[] tmp = cipher.doFinal(key.getEncoded());

			Signature sign = Signature.getInstance("SHA1withRSA");
			sign.initSign(myKey);
			sign.update(tmp);
			byte[] signed = sign.sign();

			ByteArrayOutputStream bos = new ByteArrayOutputStream(8192);
			ObjectOutputStream objData = new ObjectOutputStream(bos);
			objData.writeObject(tmp);
			objData.writeObject(signed);
			return bos.toByteArray();
		} catch (Exception e) {
			// TODO reportar error de algoritmo
			e.printStackTrace();
			return null;
		}

	}

	/**
	 * Decodifica la llave simétrica, verifica la firma digital mediante la llave publica del propietario
	 * y se decodifica mediante la llave privada de la autoridad certificadora.
	 * 
	 * @param in llave codificada
	 * @param CAKey llave privada de la autoridad certificadora
	 * @param DRKey llave publica del propietario
	 * 
	 * @return llave simétrica decodificada
	 */
	public static SecretKey unpackKey(byte[] in, RSAPrivateKey CAKey, RSAPublicKey DRKey) {
		try {
			ByteArrayInputStream ins = new ByteArrayInputStream(in);
			ObjectInputStream ois = new ObjectInputStream(ins);
			byte[] data = (byte[]) ois.readObject();
			byte[] sign = (byte[]) ois.readObject();
			Signature verify = Signature.getInstance("SHA1withRSA");
			verify.initVerify(DRKey);
			verify.update(data);
			if (!verify.verify(sign)) {
				// TODO reportar error de firma
				return null;
			}
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, CAKey);
			byte[] tmp = cipher.doFinal(data);
			return (SecretKey) new SecretKeySpec(tmp, "AES");
		} catch (Exception e) {
			e.printStackTrace();
			// TODO reportar error de algoritmo
			return null;
		}
	}

	/**
	 * Codifica el contenido de un archivo
	 * 
	 * @param key llave simétrica
	 * @param fileToCipher archivo a encriptar
	 * @param fileCiphered archivo con contenido encriptado
	 * 
	 * @throws IOException Signals that an I/O exception has occurred.
	 * @throws GeneralSecurityException the general security exception
	 */
	public static void encodeFile(SecretKey key, File fileToCipher, File fileCiphered) throws IOException, GeneralSecurityException {
		SecretKeySpec skeySpec = new SecretKeySpec(key.getEncoded(), "AES");
		Cipher cipher = Cipher.getInstance("AES");
		
		byte[] buf = new byte[16384];
		InputStream in = new FileInputStream(fileToCipher);
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
		
		OutputStream out = new CipherOutputStream(new FileOutputStream(fileCiphered), cipher);
		int numRead = 0;
		
		while ((numRead = in.read(buf)) >= 0) {
			out.write(buf, 0, numRead);
		}
		
		in.close();
		out.close();
	}

	/**
	 * Decodifica un archivo
	 * 
	 * @param key llave simetrica
	 * @param fileToCipher archivo a decodificar
	 * @param fileCiphered archivo con contenido plano
	 * 
	 * @throws IOException Signals that an I/O exception has occurred.
	 * @throws GeneralSecurityException the general security exception
	 */
	public static void decodeFile(SecretKey key, File fileToCipher, File fileCiphered) throws IOException, GeneralSecurityException {
		SecretKeySpec skeySpec = new SecretKeySpec(key.getEncoded(), "AES");
		
		Cipher cipher = Cipher.getInstance("AES");
		byte[] buf = new byte[16384];
		InputStream in = new FileInputStream(fileToCipher);
		cipher.init(Cipher.DECRYPT_MODE, skeySpec);
		
		OutputStream out = new CipherOutputStream(new FileOutputStream(fileCiphered), cipher);
		int numRead = 0;
		
		while ((numRead = in.read(buf)) >= 0) {
			out.write(buf, 0, numRead);
		}
		
		in.close();
		out.close();
	}

	/**
	 * Genera un certificado digital X509
	 * 
	 * @param cert certificado
	 * 
	 * @return certificado X509
	 * 
	 * @throws CertificateException
	 */
	public static Certificate getCertificate(byte[] cert) throws CertificateException {
		CertificateFactory cf = null;
		cf = CertificateFactory.getInstance("X509");
		java.security.cert.Certificate own = cf.generateCertificate(new ByteArrayInputStream(cert));
		return own;
	}

}
