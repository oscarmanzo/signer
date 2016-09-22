package test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import mx.gob.sfp.compranethc.firma.CertificateFPService;
import mx.gob.sfp.compranethc.firma.CertificateService;
import mx.gob.sfp.compranethc.utils.PropertiesLoader;
import mx.gob.sfp.compranethc.utils.Utils;
import mx.gob.sfp.compranethc.utils.Catalogos.CERTIFICATE_OCSP_STATUS;
import mx.gob.sfp.compranethc.utils.Catalogos.CERTIFICATE_VALID_CODE;

import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

public class FirmaTest {

	private static String PATH;
	private static String certificatePath;
	private static String privateKeyPath;
	private static String password;
	
	private static String documentPath;
	private static String pathPkcs7;

	private static String documentVerifiedPath;
	
	@BeforeClass
	public static void init(){
		PATH = "C:\\Users\\oscar.manzo\\Infotec\\Funcion Publica\\Documentos\\firma\\";
		certificatePath = PATH + "CEN-CERTIFICADO.cer";
		privateKeyPath = PATH + "CEN-LLAVE.KEY";
		password = "cenpru13";
		
		documentPath = "C:\\Users\\oscar.manzo\\Infotec\\Funcion Publica\\Documentos\\Compranet\\sfp_compranet_hc_entrevista.docx";
		pathPkcs7 = "C:\\Users\\oscar.manzo\\Infotec\\Funcion Publica\\Documentos\\Compranet\\sfp_compranet_hc_entrevista.p7b";

		documentVerifiedPath = "C:\\Users\\oscar.manzo\\Infotec\\Funcion Publica\\Documentos\\Compranet\\docto_verificado.docx";;
	}

	@Ignore
	@Test
	public void readCertificateIsValid() {
		
		try {
			CertificateService services = CertificateFPService.getInstance();

			X509Certificate certificate = services.readCertificate(certificatePath);
			assertNotNull(certificate);
			
			CERTIFICATE_VALID_CODE code = services.isValid(certificate);
			assertTrue(code == CERTIFICATE_VALID_CODE.VALID);
			
			PublicKey publicKey = certificate.getPublicKey();
			assertNotNull(publicKey);

			System.out.println("+++++++++++++++++++++++++++++++++ CERTIFICATE +++++++++++++++++++++++++++++++++++++++++++");
			System.out.println(certificate.toString());

			System.out.println("+++++++++++++++++++++++++++++++++ PUBLIC KEY +++++++++++++++++++++++++++++++++++++++++++");
			System.out.println(publicKey.toString());
			
		} catch(Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}

	}

	@Ignore
	@Test	
	public void readPrivateKey() {

		try {
			CertificateService services = CertificateFPService.getInstance();

			PrivateKey privateKey = services.readPrivateKey(privateKeyPath, password);
			assertNotNull(privateKey);

			System.out.println("+++++++++++++++++++++++++++++++++ PRIVATE KEY +++++++++++++++++++++++++++++++++++++++++++");
			System.out.println(privateKey.toString());

		} catch(Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}

	}
	
	@Ignore
	@Test
	public void signDocument(){
		try{
			CertificateService services = CertificateFPService.getInstance();

			X509Certificate certificate = services.readCertificate(certificatePath);
			assertNotNull(certificate);
			
			CERTIFICATE_VALID_CODE code = services.isValid(certificate);
			assertTrue(code == CERTIFICATE_VALID_CODE.VALID);
			
			PrivateKey privateKey = services.readPrivateKey(privateKeyPath, password);
			assertNotNull(privateKey);
			
			//byte[] document = Utils.getFile(documentPath);
			byte[] document = "SALE540422QC8".getBytes();
			
			byte[] pkcs7 = services.signDocument(certificate, privateKey, document);

			Utils.saveFile(pathPkcs7, pkcs7);

		} catch(Exception e) {
			e.printStackTrace();
			fail(e.toString());
		}
	}

	@Ignore
	@Test
	public void extractDocument() {
		try{
			byte[] pkcs7 = Utils.getFile(pathPkcs7);
			
			CertificateService services = CertificateFPService.getInstance();
			byte[] document = services.extractDocument(pkcs7);

			assertNotNull(document);
			System.out.println("Cadena extraida: "+ new String(document));
			
			//Utils.saveFile(documentVerifiedPath, document);
			
		}catch(Exception e){
			e.printStackTrace();
			fail(e.toString());
		}
	}
	
	@Ignore
	@Test
	public void verificaFirma() {
		try{
			byte[] pkcs7 = Utils.getFile(pathPkcs7);
			
			CertificateService services = CertificateFPService.getInstance();
			CERTIFICATE_VALID_CODE status = services.verifySign(pkcs7);

			assertNotNull(status);
			System.out.println("verificaFirma:"+ status.name());
			
		}catch(Exception e){
			e.printStackTrace();
			fail(e.toString());
		}
	}
	
	@Ignore
	@Test
	public void isValidInOSCP_SFP(){
		System.out.println("+++++++++++ OCSP SFP +++++++++++++");
		try{
			PropertiesLoader properties = PropertiesLoader.getInstance();
			String ocspCer = properties.getProperty("ocsp.sfp.cer");
			String ocspUrl = properties.getProperty("ocsp.sfp.url");		
			String ocspPort= properties.getProperty("ocsp.sfp.port");
			int port = Utils.parseInt(ocspPort);

			CertificateService services = CertificateFPService.getInstance();
			
			X509Certificate issuerCertificate = services.readCertificate(ocspCer);
			
			X509Certificate certificate = services.readCertificate(certificatePath);

			CERTIFICATE_OCSP_STATUS ocspCOde = services.isValidOSCP(certificate, issuerCertificate, ocspUrl +":"+ port);
			
			assertNotNull(ocspCOde);
			System.out.println("Respuesta OCSP SFP:"+ ocspCOde.name());
			
		}catch(Exception e){
			e.printStackTrace();
			fail(e.toString());
		}
	}
	
	@Ignore
	@Test
	public void isValidInOSCP_SAT(){
		System.out.println("+++++++++++ OCSP SAT +++++++++++++");
		
		try{
			certificatePath = "C:\\Users\\oscar.manzo\\Infotec\\Funcion Publica\\Documentos\\ERICK_CERTIFICADO.cer";
			
			PropertiesLoader properties = PropertiesLoader.getInstance();
			String ocspCer = properties.getProperty("ocsp.sat.cer");
			String ocspUrl = properties.getProperty("ocsp.sat.url");		
			String ocspPort= properties.getProperty("ocsp.sat.port");
			int port = Utils.parseInt(ocspPort);

			CertificateService services = CertificateFPService.getInstance();
			
			X509Certificate issuerCertificate = services.readCertificate(ocspCer);
			
			X509Certificate certificate = services.readCertificate(certificatePath);

			CERTIFICATE_OCSP_STATUS ocspCOde = services.isValidOSCP(certificate, issuerCertificate, ocspUrl +":"+ port);
			
			assertNotNull(ocspCOde);
			System.out.println("Respuesta OCSP SAT:"+ ocspCOde.name());
			
		}catch(Exception e){
			e.printStackTrace();
			fail(e.toString());
		}
	}
}
