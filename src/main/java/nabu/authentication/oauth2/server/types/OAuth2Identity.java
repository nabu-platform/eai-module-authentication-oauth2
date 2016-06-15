package nabu.authentication.oauth2.server.types;

import javax.xml.bind.annotation.XmlElement;

public class OAuth2Identity {
	
	private String accessToken, refreshToken, tokenType;
	private Integer expiresIn;
	
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
	
	@XmlElement(name = "refresh_token")
	public String getRefreshToken() {
		return refreshToken;
	}
	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}
	
}
