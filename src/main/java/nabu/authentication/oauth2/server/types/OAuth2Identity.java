package nabu.authentication.oauth2.server.types;

import javax.xml.bind.annotation.XmlElement;

public class OAuth2Identity {
	
	private String accessToken, tokenType;
	private Integer expiresIn;
	
	@XmlElement(name = "access_token")
	public String getAccessToken() {
		return accessToken;
	}
	@XmlElement(name = "expires_in")
	public Integer getExpiresIn() {
		return expiresIn;
	}
	@XmlElement(name = "token_type")
	public String getTokenType() {
		return tokenType;
	}
	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}
	public void setTokenType(String tokenType) {
		this.tokenType = tokenType;
	}
	public void setExpiresIn(Integer expiresIn) {
		this.expiresIn = expiresIn;
	}
}
