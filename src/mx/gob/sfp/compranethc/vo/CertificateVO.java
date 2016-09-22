package mx.gob.sfp.compranethc.vo;

import java.math.BigInteger;
import java.util.Date;

/**
 *
 * @author oscar.manzo
 */
public class CertificateVO {
    
    private BigInteger serialNumber;
    private SubjectVO issuer;
    private SubjectVO subject;
    private byte[] publicKey;
    private Date begin;
    private Date end;

    public BigInteger getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(BigInteger serialNumber) {
        this.serialNumber = serialNumber;
    }

    public SubjectVO getIssuer() {
        return issuer;
    }

    public void setIssuer(SubjectVO issuer) {
        this.issuer = issuer;
    }

    public SubjectVO getSubject() {
        return subject;
    }

    public void setSubject(SubjectVO subject) {
        this.subject = subject;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public Date getBegin() {
        return begin;
    }

    public void setBegin(Date begin) {
        this.begin = begin;
    }

    public Date getEnd() {
        return end;
    }

    public void setEnd(Date end) {
        this.end = end;
    }

    @Override
    public String toString() {
        return "CertificateVO{" + " issuer=" + issuer + ", subject=" + subject + ", publicKey=" + publicKey + ", begin=" + begin + ", end=" + end + '}';
    }

}
