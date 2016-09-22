package test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.security.cert.X509Certificate;

import mx.gob.sfp.compranethc.firma.CertificateAdvantageService;
import mx.gob.sfp.compranethc.firma.CertificateFPService;
import mx.gob.sfp.compranethc.firma.CertificateService;
import mx.gob.sfp.compranethc.utils.Catalogos.CERTIFICATE_OCSP_STATUS;

import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

public class FirmaOCSPTest {

    private static String sat_url;
    private static String sat_port;
    private static String sat_cert;
    
    private static String sfp_url;
    private static String sfp_port;
    private static String sfp_cert;

    @BeforeClass
    public static void init(){
        sfp_url = "http://200.77.236.81";
        sfp_port = "8083";
        //sfp_port = "";
        sfp_cert = "C:\\Users\\oscar.manzo\\Infotec\\Funcion Publica\\Documentos\\Certificados CA SFP\\AZ_new_AGCer_210613.cer";

        sat_url = "http://www.sat.gob.mx/ocsp";
        sat_port = "";
        sat_cert = "C:\\Users\\oscar.manzo\\Infotec\\Funcion Publica\\Documentos\\Certificados CA SAT\\AC-Sat1070.crt";    
    }

    //@Ignore
    @Test
    public void isValidInOSCP_SFP(){

        String[] paths = {"C:\\Users\\oscar.manzo\\Infotec\\Funcion Publica\\Documentos\\Certificados del SFP\\CEN-CERTIFICADO.cer",
                          "C:\\Users\\oscar.manzo\\Infotec\\Funcion Publica\\Documentos\\Certificados del SFP\\cen2013.cer"};

        String url = sfp_url;

        if (sfp_port!=null && !sfp_port.isEmpty()){
            url = sfp_url +":"+ sfp_port;
        }

        for (String certificatePath : paths){
            isValidInOSCP("SFP", certificatePath, sfp_cert, url);    
        }
    }

    //@Ignore
    @Test
    public void isValidInOSCP_SAT(){

        String[] paths = {"C:\\Users\\oscar.manzo\\Infotec\\Funcion Publica\\Documentos\\Certificados del SAT\\ERICK_CERTIFICADO.cer",
                          "C:\\Users\\oscar.manzo\\Infotec\\Funcion Publica\\Documentos\\Certificados del SAT\\firma jahv\\00001000000103039084.cer"};

        String url = sat_url;

        if (sat_port!=null && !sat_port.isEmpty()){
            url = sat_url +":"+ sat_port;
        }

        for (String certificatePath : paths){
            isValidInOSCP("SAT", certificatePath, sat_cert, url);            
        }
    }

    private void isValidInOSCP(String CA, String certificatePath, String ocspCACer, String ocspCAUrl){

        System.out.println("+++++++++++ OCSP "+ CA +" +++++++++++++");

        try{
            CertificateService servicesSFP = CertificateFPService.getInstance();
            CertificateService servicesAVS = CertificateAdvantageService.getInstance();

            X509Certificate issuerCertificate = servicesSFP.readCertificate(ocspCACer);
            X509Certificate subjectCertificate = servicesSFP.readCertificate(certificatePath);

            CERTIFICATE_OCSP_STATUS ocspCOde = servicesAVS.isValidOSCP(subjectCertificate, issuerCertificate, ocspCAUrl);

            assertNotNull(ocspCOde);
            System.out.println("Respuesta OCSP "+ CA +": "+ ocspCOde.name() +"\n\n");

        }catch(Exception e){
            e.printStackTrace();
            fail(e.toString());
        }
    }

}