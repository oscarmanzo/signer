package mx.gob.sfp.compranethc.vo;

import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

/**
 *
 * @author oscar.manzo
 */
public class SubjectVO {
  
    private String commonName;
    private String country;
    private String locality;
    private String statePrivate;
    private String address;
    private String organization;
    private String organizationUnit;
    private String academicDegree;
    private String postalCode;
    private String federalRegistry;
    private String email;

    private final List<IdentifierVO> identifiers;
    
    public SubjectVO(){
        this.identifiers = new ArrayList<IdentifierVO>();
    }
    
    public void addIdentifier(IdentifierVO extension){
        identifiers.add(extension);
    }

    public String findIdentifierValue(String oid){
        for (IdentifierVO identifier : identifiers){
            if (identifier.getOID().equalsIgnoreCase(oid)){
                return identifier.getValue();
            }
        }
        return null;
    }

    	/*private String GetSubjectName(String oid, String strSubject) {
		int pos = strSubject.indexOf(new StringBuilder().append(oid).append("=").toString(), 0);
		if (pos < 0) return "";

		String strValue = strSubject.substring(pos + oid.length() + 1);
		if (strValue.charAt(0) == '"') {
			pos = strValue.indexOf("\"", 1);
			if (pos >= 0)
				strValue = strValue.substring(1, pos);
		} else {
			pos = strValue.indexOf(",");
			if (pos >= 0)
				strValue = strValue.substring(0, pos);
		}
		return strValue;
	}*/

    
    public SubjectVO parseIdentifiers(String dn){
        // TODO corregir parseo de valores
    
        StringTokenizer tokens = new StringTokenizer(dn, ",", true);
        
        while (tokens.hasMoreTokens()){
            String token = tokens.nextToken();
            
            if (token.contains("=")){
                String oid = token.substring(0, token.indexOf("="));
                String value = token.substring(token.indexOf("=")+1);
                
                addIdentifier(IdentifierVO.getInstance(oid.trim(), value.trim()));
            }
        }
        
        return this;
    }

    public List<IdentifierVO> getIdentifiers() {
        return identifiers;
    }
   
    public String getCommonName() {
        return commonName;
    }

    public void setCommonName(String commonName) {
        this.commonName = commonName;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    public String getLocality() {
        return locality;
    }

    public void setLocality(String locality) {
        this.locality = locality;
    }

    public String getStatePrivate() {
        return statePrivate;
    }

    public void setStatePrivate(String statePrivate) {
        this.statePrivate = statePrivate;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public String getOrganization() {
        return organization;
    }

    public void setOrganization(String organization) {
        this.organization = organization;
    }

    public String getOrganizationUnit() {
        return organizationUnit;
    }

    public void setOrganizationUnit(String organizationUnit) {
        this.organizationUnit = organizationUnit;
    }

    public String getAcademicDegree() {
        return academicDegree;
    }

    public void setAcademicDegree(String academicDegree) {
        this.academicDegree = academicDegree;
    }

    public String getPostalCode() {
        return postalCode;
    }

    public void setPostalCode(String postalCode) {
        this.postalCode = postalCode;
    }

    public String getFederalRegistry() {
        return federalRegistry;
    }

    public void setFederalRegistry(String federalRegistry) {
        this.federalRegistry = federalRegistry;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    @Override
    public String toString() {
        return "SubjectVO{" + "commonName=" + commonName + ", country=" + country + ", locality=" + locality + ", statePrivate=" + statePrivate + ", address=" + address + ", organization=" + organization + ", organizationUnit=" + organizationUnit + ", academicDegree=" + academicDegree + ", postalCode=" + postalCode + ", federalRegistry=" + federalRegistry + ", email=" + email + ", identifiers=" + identifiers + '}';
    }

}
