package mx.gob.sfp.compranethc.utils;

public final class Catalogos {

	private Catalogos(){}

	public enum CERTIFICATE_VALID_CODE {
		VALID,
		EXPIRED,
		NOT_YET_VALID;
	}

	public enum CERTIFICATE_OCSP_STATUS {
		GOOD,
		REVOKED,
		UNKNOWN;
	}

}