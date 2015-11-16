package nabu.types;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "oAuth2Token")
public class OAuth2Token {
	
	private String accessToken;
	private Integer expiresIn;
	private String tokenType;
	
	@XmlElement(name = "access_token")
	public String getAccessToken() {
		return accessToken;
	}
	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}
	
	@XmlElement(name = "expires_in")
	public Integer getExpiresIn() {
		return expiresIn;
	}
	public void setExpiresIn(Integer expiresIn) {
		this.expiresIn = expiresIn;
	}
	
	@XmlElement(name = "token_type")
	public String getTokenType() {
		return tokenType;
	}
	public void setTokenType(String tokenType) {
		this.tokenType = tokenType;
	}
}
