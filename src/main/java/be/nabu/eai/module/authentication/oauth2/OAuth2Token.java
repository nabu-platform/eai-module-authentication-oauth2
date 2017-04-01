package be.nabu.eai.module.authentication.oauth2;

import java.security.Principal;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import nabu.authentication.oauth2.server.types.OAuth2Identity;
import be.nabu.libs.authentication.api.Token;

public class OAuth2Token implements Token {

	private static final long serialVersionUID = 1L;
	
	private OAuth2Identity token;
	private String realm;
	private Date validUntil;
	// we generate a random name
	// in the past we returned the access token as name but this can be a security leak, especially when embedding in a JWT token
	// if you are using an oauth2 token, you likely do not have an actual local identity for the user
	// as such it doesn't matter too much
	private String name = UUID.randomUUID().toString().replace("-", "");

	public OAuth2Token() {
		// auto construct
	}
	
	public OAuth2Token(OAuth2Identity token, String realm) {
		this.token = token;
		this.realm = realm;
		// the expiry timeout is expressed in seconds
		this.validUntil = token instanceof OAuth2IdentityWithContext
			? ((OAuth2IdentityWithContext) token).getExpired() 
			: new Date(new Date().getTime() + (token.getExpiresIn() * 1000));
	}
	
	@Override
	public String getName() {
		return name;
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
