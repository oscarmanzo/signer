package mx.gob.sfp.compranethc.firma;

import java.math.BigInteger;
import java.util.Date;

import mx.gob.sfp.compranethc.utils.Catalogos.CERTIFICATE_VALID_CODE;

public class CertificateData {

	private CERTIFICATE_VALID_CODE code;
	private byte[] document;

	private BigInteger serialNumber;
	private byte[] serie;
	private String issuer;
	private String subject;
	private byte[] publicKey;
	private Date begin;
	private Date end;

	public CERTIFICATE_VALID_CODE getCode() {
		return code;
	}

	public void setCode(CERTIFICATE_VALID_CODE code) {
		this.code = code;
	}

	public byte[] getDocument() {
		return document;
	}

	public void setDocument(byte[] document) {
		this.document = document;
	}

	public BigInteger getSerialNumber() {
		return serialNumber;
	}

	public void setSerialNumber(BigInteger serialNumber) {
		this.serialNumber = serialNumber;
	}

	public byte[] getSerie() {
		return serie;
	}

	public void setSerie(byte[] serie) {
		this.serie = serie;
	}

	public String getIssuer() {
		return issuer;
	}

	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}

	public String getSubject() {
		return subject;
	}

	public void setSubject(String subject) {
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
	
}
