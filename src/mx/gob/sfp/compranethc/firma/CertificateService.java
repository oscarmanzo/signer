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

import mx.gob.sfp.compranethc.utils.Catalogos.CERTIFICATE_OCSP_STATUS;
import mx.gob.sfp.compranethc.utils.Catalogos.CERTIFICATE_VALID_CODE;
import mx.gob.sfp.compranethc.vo.CertificateVO;

public interface CertificateService {

        public X509Certificate readCertificate(File certificate) throws IOException, CertificateException;
    
	public X509Certificate readCertificate(String path) throws IOException, CertificateException;
	
	public X509Certificate readCertificate(byte[] certificate) throws CertificateException;
	
	public X509Certificate readCertificate(InputStream inputStream) throws CertificateException;
	
        public PrivateKey readPrivateKey(File privateKey, String password) throws IOException, GeneralSecurityException;
        
	public PrivateKey readPrivateKey(String privateKeyPath, String password) throws IOException, GeneralSecurityException;
	
	public PrivateKey readPrivateKey(byte[] privateKeyBytes, String password) throws GeneralSecurityException;
	
	public CertificateData extractData(X509Certificate certificate);
	
	public boolean checkOwner(byte[] certificate, String name) throws CertificateException;
	
	public boolean checkOwner(X509Certificate certificate, String name);
	
	public CERTIFICATE_VALID_CODE isValid(X509Certificate certificate);
	
	public CERTIFICATE_VALID_CODE isValid(X509Certificate certificate, Date date);
	
	public byte[] signDocument(X509Certificate certificate, PrivateKey privateKey, byte[] document) throws CertificateException;
	
	public CERTIFICATE_VALID_CODE verifySign(byte[] pkcs7) throws CertificateException;
	
	public byte[] extractDocument(byte[] pkcs7) throws CertificateException;
	
	public CERTIFICATE_OCSP_STATUS isValidOSCP(BigInteger serialNumber, X509Certificate issuerCertificate, String urlOCSP);
	
	public CERTIFICATE_OCSP_STATUS isValidOSCP(X509Certificate certificate, X509Certificate issuerCertificate, String urlOCSP);

        public CertificateVO loadCertificate(X509Certificate certificate);
}
