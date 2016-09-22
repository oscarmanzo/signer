package mx.gob.sfp.compranethc.vo;

/**
 *
 * @author oscar.manzo
 */
public class IdentifierVO {

    private String OID;
    private String value;
    
    private IdentifierVO(){}
    
    public static final IdentifierVO getInstance(String OID, String value){
        IdentifierVO extension = new IdentifierVO();
        extension.OID = OID;
        extension.value = value;
        return extension;
    }

    public String getOID() {
        return OID;
    }

    public String getValue() {
        return value;
    }

    @Override
    public String toString() {
        return "ExtensionVO{" + "OID=" + OID + ", value=" + value + '}';
    }

}
