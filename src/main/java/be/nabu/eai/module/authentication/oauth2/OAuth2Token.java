package be.nabu.eai.module.authentication.oauth2;

import java.security.Principal;
import java.util.Date;
import java.util.List;

import nabu.authentication.oauth2.server.types.OAuth2Identity;
import be.nabu.libs.authentication.api.Token;

public class OAuth2Token implements Token {

	private static final long serialVersionUID = 1L;
	
	private OAuth2Identity token;
	private String realm;
	private Date validUntil;

	public OAuth2Token() {
		// auto construct
	}
	
	public OAuth2Token(OAuth2Identity token, String realm) {
		this.token = token;
		this.realm = realm;
		// the expiry timeout is expressed in seconds
		this.validUntil = new Date(new Date().getTime() + (token.getExpiresIn() * 1000));
	}
	
	@Override
	public String getName() {
		return token.getAccessToken();
	}

	@Override
	public String getRealm() {
		return realm;
	}

	@Override
	public Date getValidUntil() {
		return validUntil;
	}

	@Override
	public List<Principal> getCredentials() {
		return null;
	}

	public OAuth2Identity getOAuth2Token() {
		return token;
	}
	
}
