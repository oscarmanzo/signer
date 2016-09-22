package mx.gob.sfp.compranethc.firma;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import mx.gob.sfp.compranethc.utils.Catalogos.CERTIFICATE_OCSP_STATUS;
import mx.gob.sfp.compranethc.utils.Catalogos.CERTIFICATE_VALID_CODE;
import mx.gob.sfp.compranethc.utils.Utils;
import mx.gob.sfp.compranethc.vo.CertificateVO;
import mx.gob.sfp.compranethc.vo.SubjectVO;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.ssl.PKCS8Key;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.ocsp.CertificateStatus;
import org.bouncycastle.ocsp.OCSPRespStatus;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

public final class CertificateFPService implements CertificateService {
	
	private final static CertificateFPService INSTANCE = new CertificateFPService();

	private CertificateFPService(){}
	
	public static final CertificateService getInstance(){
		return INSTANCE;
	}

        @Override
	public X509Certificate readCertificate(File certificate) throws IOException, CertificateException{
        	byte[] data = Utils.getBytes(new FileInputStream(certificate));
		return readCertificate(data);
	}
        
	@Override
	public X509Certificate readCertificate(String path) throws IOException, CertificateException{
		byte[] data = Utils.getFile(path);
		return readCertificate(data);
	}
	
	@Override
	public X509Certificate readCertificate(byte[] certificate) throws CertificateException{
		InputStream inputStream = new ByteArrayInputStream(certificate);

		return readCertificate(inputStream);
	}
	
	@Override
	public X509Certificate readCertificate(InputStream inputStream) throws CertificateException{
		
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		X509Certificate rsa = (X509Certificate)certificateFactory.generateCertificate(inputStream);
		
		return rsa;
	}

        @Override
	public PrivateKey readPrivateKey(File privateKey, String password) throws IOException, GeneralSecurityException{
		byte[] privateKeyBytes = Utils.getBytes(new FileInputStream(privateKey));
		return readPrivateKey(privateKeyBytes, password);
	}
        
	@Override
	public PrivateKey readPrivateKey(String privateKeyPath, String password) throws IOException, GeneralSecurityException{
		byte[] privateKeyBytes = Utils.getFile(privateKeyPath);
		return readPrivateKey(privateKeyBytes, password);
	}
	
	@Override
	public PrivateKey readPrivateKey(byte[] privateKeyBytes, String password) throws GeneralSecurityException{

		PKCS8Key pkcs8 = new PKCS8Key(privateKeyBytes, password.toCharArray());
		byte[] binStruct = pkcs8.getDecryptedBytes();

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(binStruct));

		return privateKey;
	}
	
	@Override
	public CERTIFICATE_VALID_CODE isValid(X509Certificate certificate){
		return isValid(certificate, null);
	}

	@Override
	public CERTIFICATE_VALID_CODE isValid(X509Certificate certificate, Date date){
		if (certificate==null) throw new IllegalArgumentException("Certificate required");
		
		try {
			if (date!=null){
				certificate.checkValidity(date);
			} else{
				certificate.checkValidity();
			}
		} catch (CertificateExpiredException e) {
			e.printStackTrace();
			return CERTIFICATE_VALID_CODE.EXPIRED;
		} catch (CertificateNotYetValidException e) {
			e.printStackTrace();
			return CERTIFICATE_VALID_CODE.NOT_YET_VALID;
		}

		return CERTIFICATE_VALID_CODE.VALID;
	}

	@Override
	public boolean checkOwner(byte[] certificate, String name) throws CertificateException{
		return checkOwner(readCertificate(certificate), name);
	}
	
	@Override
	public boolean checkOwner(X509Certificate certificate, String name){
		CertificateData data = extractData(certificate);
		boolean isOwner = data.getSubject().equals(name);
        return isOwner;  
	}

	@Override
	public CertificateData extractData(X509Certificate certificate){
		if (certificate==null) throw new IllegalArgumentException("Certificate required");
		
		CertificateData data = new CertificateData();
		data.setSerialNumber(certificate.getSerialNumber());
		data.setPublicKey	(certificate.getPublicKey().getEncoded());
		data.setIssuer		(certificate.getIssuerDN().getName());
		data.setSubject		(certificate.getSubjectDN().getName());
		data.setBegin		(certificate.getNotBefore());
		data.setEnd			(certificate.getNotAfter());
		return data;
	}
	
	@Override
	public byte[] signDocument(X509Certificate certificate, PrivateKey privateKey, byte[] document) throws CertificateException{

		byte[] pcks7 = null;
		
		try{
	        Security.addProvider(new BouncyCastleProvider());

	        //PrivateKey privKey = (PrivateKey) key;
	        Signature signature = Signature.getInstance("SHA1WithRSA", "BC");
	        signature.initSign(privateKey);
	        signature.update(document);
			System.out.println("sign:"+ Base64.encodeBase64String(signature.sign()));
			//System.out.println("Signature Arrays:"+ Arrays.toString(signature.sign()));
	        
	        CMSTypedData msg = new CMSProcessableByteArray(document);

	        List<X509Certificate> certificates = new ArrayList<X509Certificate>();
	        certificates.add(certificate);
	        Store certs = new JcaCertStore(certificates);

	        CMSSignedDataGenerator signedDataGenerator = new CMSSignedDataGenerator();

	        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(privateKey);
	        //System.out.println("Signature:"+ Base64.encodeBase64String(sha1Signer.getSignature()));
	        
	        signedDataGenerator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(sha1Signer, certificate));
	        signedDataGenerator.addCertificates(certs);
	        
	        CMSSignedData cmsSignedData = signedDataGenerator.generate(msg, true);

	        pcks7 = cmsSignedData.getEncoded();
	        
		} catch (Exception e){
			e.printStackTrace();
			throw new CertificateException(e);
		}

        return pcks7;
	}

	@Override
	public CERTIFICATE_VALID_CODE verifySign(byte[] pkcs7) throws CertificateException {
		CERTIFICATE_VALID_CODE code = null;
		
		CertificateData data = verifySignGetDocument(pkcs7);
		
		if (data!=null){
			code = data.getCode();
		}

		return code;
	}
	
	@Override
	public byte[] extractDocument(byte[] pkcs7) throws CertificateException {
		
		byte[] document = null;
		
		CertificateData data = verifySignGetDocument(pkcs7);
		
		if (data!=null){
			document = data.getDocument();
		}

		return document;
	}
	
	@SuppressWarnings("rawtypes")
	private CertificateData verifySignGetDocument(byte[] pkcs7) throws CertificateException {
		CertificateData data = null;

		try {

			CERTIFICATE_VALID_CODE code = CERTIFICATE_VALID_CODE.NOT_YET_VALID;
			byte[] content = null;
			
			Security.addProvider(new BouncyCastleProvider());

			CMSSignedData cms = new CMSSignedData(pkcs7);
			Store store = cms.getCertificates();
			SignerInformationStore signers = cms.getSignerInfos();
			
			Collection c = signers.getSigners();
			Iterator it = c.iterator();
			
			while (it.hasNext()) {
				SignerInformation signer = (SignerInformation) it.next();
				Collection certCollection = store.getMatches(signer.getSID());
				Iterator certIt = certCollection.iterator();

				X509CertificateHolder certHolder = (X509CertificateHolder) certIt.next();
				X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
				
				if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert))) {

					code = CERTIFICATE_VALID_CODE.VALID;

					CMSProcessableByteArray cpb = (CMSProcessableByteArray)cms.getSignedContent();
					content = (byte[])cpb.getContent();

					System.out.println(Calendar.getInstance().getTimeInMillis());
					System.out.println("Content:"+ new String(content));
					
					System.out.println("Digest:"+ Base64.encodeBase64String(signer.getContentDigest()));
					System.out.println("Signature:"+ Base64.encodeBase64String(signer.getSignature()));
//					System.out.println("Signature.getOctets:"+ Base64.encodeBase64String(signer.toASN1Structure().getEncryptedDigest().getOctets()));
//					System.out.println("Signature.getEncoded:"+ Base64.encodeBase64String(signer.toASN1Structure().getEncryptedDigest().getEncoded()));
//					
//					System.out.println("Signature Arrays:"+ Arrays.toString(signer.getSignature()));
//					System.out.println("Signature:"+ Base64.encodeBase64String(signer.getSignature()));
				}
			}
			
			data = new CertificateData();
			data.setCode(code);
			data.setDocument(content);

		} catch (Exception e){
			e.printStackTrace();
			throw new CertificateException(e);
		}

		return data;
	}
        
	@Override
	public CERTIFICATE_OCSP_STATUS isValidOSCP(X509Certificate certificate, X509Certificate issuerCertificate, String urlOCSP){
		return isValidOSCP(certificate.getSerialNumber(), issuerCertificate, urlOCSP);
	}
	
	@Override
	public CERTIFICATE_OCSP_STATUS isValidOSCP(BigInteger serialNumber, X509Certificate issuerCertificate, String urlOCSP) {

            System.out.println("urlOCSP:"+ urlOCSP);
            System.out.println("serialNumber:"+ serialNumber.intValue());

            CERTIFICATE_OCSP_STATUS code = CERTIFICATE_OCSP_STATUS.UNKNOWN;

            try {
                OCSPReq request = generateOCSPRequest(issuerCertificate, serialNumber);

                //List<String> locations = getAIALocations(peerCert);

                OCSPResp ocspResponse = getOCSPResponce(urlOCSP, request);
                
                System.out.println("ocspResponse.status: "+ ocspResponse.getStatus());
                
                if (OCSPRespStatus.SUCCESSFUL == ocspResponse.getStatus()){
                        System.out.println("server gave response fine");
                } else {
                        System.out.println("server gave response error");
                }

                BasicOCSPResp basicResponse = (BasicOCSPResp)ocspResponse.getResponseObject();

                SingleResp[] responses = (basicResponse == null) ? null : basicResponse.getResponses();

                if (responses != null && responses.length == 1) {
                    SingleResp resp = responses[0];

                    Object status = resp.getCertStatus();

                    if (status == CertificateStatus.GOOD) {
                        System.out.println("OCSP Status is good!");
                        code = CERTIFICATE_OCSP_STATUS.GOOD;
                    } else if (status instanceof org.bouncycastle.ocsp.RevokedStatus ||
                               status instanceof org.bouncycastle.cert.ocsp.RevokedStatus) {
                        System.out.println("OCSP Status is revoked!");
                        code = CERTIFICATE_OCSP_STATUS.REVOKED;
                    } else if (status instanceof org.bouncycastle.ocsp.UnknownStatus ||
                               status instanceof org.bouncycastle.cert.ocsp.UnknownStatus) {
                        System.out.println("OCSP Status is unknown!");
                        code = CERTIFICATE_OCSP_STATUS.UNKNOWN;
                    }

//                  if (status != null) {} else {
//                      code = CERTIFICATE_OCSP_STATUS.GOOD;
//                  }
                }

            } catch (Exception e) {
                e.printStackTrace();
            }

            return code;
	}

    @Override
    public String toString() {
        return "CertificateFPService{" + '}';
    }

    private OCSPReq generateOCSPRequest(X509Certificate issuerCert, BigInteger serialNumber) throws Exception {

        //Add provider BC
        Security.addProvider(new BouncyCastleProvider());
        try {
            //  CertID structure is used to uniquely identify certificates that are the subject of
            // an OCSP request or response and has an ASN.1 definition. CertID structure is defined in RFC 2560
            //CertificateID id = new CertificateID(CertificateID.HASH_SHA1, issuerCert, serialNumber);

            // basic request generation with nonce
            OCSPReqBuilder generator = new OCSPReqBuilder();
            //generator.addRequest(id);

            DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
            generator.addRequest(new JcaCertificateID(digCalcProv.get(CertificateID.HASH_SHA1), issuerCert, serialNumber));

            // create details for nonce extension. The nonce extension is used to bind
            // a request to a response to prevent replay attacks. As the name implies,
            // the nonce value is something that the client should only use once within a reasonably small period.
            BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());

            //List objectIdentifiers = new ArrayList();
            //List values = new ArrayList();

            //to create the request Extension
            //objectIdentifiers.add(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            //values.add(new X509Extension(false, new DEROctetString(nonce.toByteArray())));
            //generator.setRequestExtensions(new Extensions(objectIdentifiers, values));

            Extension[] extensions = new Extension[1];
            extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(nonce.toByteArray()));
            generator.setRequestExtensions(new Extensions(extensions));


            //return generator.generate();
            return generator.build();

        } catch (Exception e) {
            e.printStackTrace();
            throw new Exception("Cannot generate OSCP Request with the given certificate",e);
        }
    }

    private OCSPResp getOCSPResponce(String serviceUrl, OCSPReq request) throws Exception {
        
        System.out.println("serviceUrl:"+ serviceUrl);
        
        try {
            byte[] array = request.getEncoded();

            if (serviceUrl.startsWith("http")) {

                HttpURLConnection con = null;

                URL url = new URL(serviceUrl);
                con = (HttpURLConnection)url.openConnection();
                con.setRequestProperty("Content-Type", "application/ocsp-request");
                con.setRequestProperty("Accept", "application/ocsp-response");
                con.setDoOutput(true);
                OutputStream out = con.getOutputStream();
                DataOutputStream dataOut = new DataOutputStream(new BufferedOutputStream(out));
                dataOut.write(array);

                dataOut.flush();
                dataOut.close();

                //Get Response
                System.out.println("ResponseMessage:"+ con.getResponseMessage());
                
                InputStream in = (InputStream)con.getContent();
                OCSPResp ocspResponse = new OCSPResp(in);
                
                System.out.println("ocspResponse:"+ ocspResponse.toString());
                
                return ocspResponse;

            } else {
                throw new Exception("Only http is supported for ocsp calls");
            }

        } catch (IOException e) {
            e.printStackTrace();
            throw new Exception("Cannot get ocspResponse from url: "+ serviceUrl, e);
        }
    }

    // TODO VERIFICAR IMPLEMENTACION
    public boolean verifica_consistencia(X509Certificate paramX509Certificate, PrivateKey paramPrivateKey) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] arrayOfByte1 = "Texto de prueba".getBytes();
        Signature localSignature1 = Signature.getInstance("SHA1withRSA");
        localSignature1.initSign(paramPrivateKey);
        localSignature1.update(arrayOfByte1);
        byte[] arrayOfByte2 = localSignature1.sign();
        Signature localSignature2 = Signature.getInstance("SHA1withRSA");
        localSignature2.initVerify(paramX509Certificate);
        localSignature2.update(arrayOfByte1);
        return localSignature2.verify(arrayOfByte2);
    }
    
    public CertificateVO loadCertificate(X509Certificate certificate){

        CertificateVO certificateData = new CertificateVO();

        certificateData.setSerialNumber(certificate.getSerialNumber());
        certificateData.setPublicKey (certificate.getPublicKey().getEncoded());
        certificateData.setIssuer    (parseSubject(certificate.getIssuerDN().getName()));
        certificateData.setSubject   (parseSubject(certificate.getSubjectDN().getName()));
        certificateData.setBegin     (certificate.getNotBefore());
        certificateData.setEnd       (certificate.getNotAfter());

        return certificateData;
    }

    private SubjectVO parseSubject(String dn) {
        if (dn==null) throw new IllegalArgumentException("Subject DN requerido");
        
        System.out.println(dn);
        
        SubjectVO subject = new SubjectVO().parseIdentifiers(dn);
        
        subject.setOrganization     (subject.findIdentifierValue("O"));
        subject.setCommonName       (subject.findIdentifierValue("CN"));
        subject.setOrganizationUnit (subject.findIdentifierValue("OU"));
        subject.setCountry          (subject.findIdentifierValue("C"));
        subject.setLocality         (subject.findIdentifierValue("L"));
        subject.setStatePrivate     (subject.findIdentifierValue("ST"));
        subject.setEmail            (subject.findIdentifierValue("EMAILADDRESS"));
        subject.setAddress          (subject.findIdentifierValue("STREE"));
        subject.setPostalCode       (subject.findIdentifierValue("OID.2.5.4.17"));
        subject.setFederalRegistry  (subject.findIdentifierValue("OID.2.5.4.45"));
        subject.setAcademicDegree   (subject.findIdentifierValue("T"));
   
        return subject;
    }

}
