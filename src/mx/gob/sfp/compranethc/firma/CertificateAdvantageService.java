package mx.gob.sfp.compranethc.firma;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import mx.gob.sfp.compranethc.utils.Utils;
import mx.gob.sfp.compranethc.utils.Catalogos.CERTIFICATE_OCSP_STATUS;
import mx.gob.sfp.compranethc.utils.Catalogos.CERTIFICATE_VALID_CODE;
import mx.gob.sfp.compranethc.vo.CertificateVO;

import org.apache.commons.codec.binary.Base64;

import fiellib.TCrypto.TCertificateInformation;

public class CertificateAdvantageService implements CertificateService {

	private final static CertificateAdvantageService INSTANCE = new CertificateAdvantageService();

	private CertificateAdvantageService(){}
	
	public static final CertificateService getInstance(){
		return INSTANCE;
	}
	
	@Override
	public X509Certificate readCertificate(File certificate) throws IOException, CertificateException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public X509Certificate readCertificate(String path) throws IOException, CertificateException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public X509Certificate readCertificate(byte[] certificate) throws CertificateException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public X509Certificate readCertificate(InputStream inputStream) throws CertificateException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public PrivateKey readPrivateKey(File privateKey, String password) throws IOException, GeneralSecurityException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public PrivateKey readPrivateKey(String privateKeyPath, String password)
			throws IOException, GeneralSecurityException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public PrivateKey readPrivateKey(byte[] privateKeyBytes, String password)
			throws GeneralSecurityException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public CertificateData extractData(X509Certificate certificate) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean checkOwner(byte[] certificate, String name)
			throws CertificateException {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean checkOwner(X509Certificate certificate, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public CERTIFICATE_VALID_CODE isValid(X509Certificate certificate) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public CERTIFICATE_VALID_CODE isValid(X509Certificate certificate, Date date) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] signDocument(X509Certificate certificate,
			PrivateKey privateKey, byte[] document) throws CertificateException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public CERTIFICATE_VALID_CODE verifySign(byte[] pkcs7)
			throws CertificateException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] extractDocument(byte[] pkcs7) throws CertificateException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public CERTIFICATE_OCSP_STATUS isValidOSCP(X509Certificate certificate, X509Certificate issuerCertificate, String urlOCSP) {
		return isValidOSCP(certificate.getSerialNumber(), issuerCertificate, urlOCSP);
	}
	
	@Override
	public CERTIFICATE_OCSP_STATUS isValidOSCP(BigInteger serialNumber, X509Certificate issuerCertificate, String urlOCSP) {

        System.out.println("urlOCSP:"+ urlOCSP);
        System.out.println("serialNumber:"+ serialNumber.intValue());
		
		byte[] userSerie = null;
		String validacion = null;
		
		try {
	    	//TCertificateInformation datosCertificado = getFileCertificate(pathToSignedFile);        	
	        userSerie = serialNumber.toByteArray();
	        
	        byte[] authorityCertificate = issuerCertificate.getEncoded();
	
	        fiellib.TOcsp ocsp = new fiellib.TOcsp();
	        fiellib.TOcsp.TOcspState state = ocsp.RequestStateCertificate(urlOCSP, userSerie, authorityCertificate, 8083);

	        if (state.response!=null && state.response.length>0){
	        	validacion = new String(Base64.encodeBase64(state.response));
	        }else if (state.descrip!=null && state.descrip.length()>0){
	        	validacion = new String(Base64.encodeBase64(state.descrip.getBytes()));
	        }else{
	        	String msg = "No se recibió validación de OCSP estado:" + state.state+ ".";
	        	validacion = new String(Base64.encodeBase64(msg.getBytes()));
	        }

	        System.out.println("state:"+ state.state +", descrip:"+ state.descrip +", validacion:"+ validacion);

    	} catch (Exception e){
    		e.printStackTrace();
    	}
    
		return CERTIFICATE_OCSP_STATUS.UNKNOWN;
	}

	@Override
	public CertificateVO loadCertificate(X509Certificate certificate) {
		// TODO Auto-generated method stub
		return null;
	}

}
