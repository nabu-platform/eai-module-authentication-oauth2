/*
* Copyright (C) 2015 Alexander Verbruggen
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

package be.nabu.eai.module.authentication.oauth2;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import nabu.authentication.oauth2.server.Services;
import nabu.authentication.oauth2.server.types.OAuth2Identity;
import be.nabu.eai.repository.EAIResourceRepository;
import be.nabu.libs.authentication.api.RefreshableToken;
import be.nabu.libs.authentication.api.Token;
import be.nabu.libs.http.jwt.JWTToken;

public class OAuth2Token implements RefreshableToken {

	private static final long serialVersionUID = 1L;
	
	private OAuth2Identity token;
	private String realm;
	private Date validUntil;
	private String name = null;
	private List<Principal> credentials = new ArrayList<Principal>();
	private Logger logger = LoggerFactory.getLogger(getClass());
	
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
		if (!credentials.isEmpty()) {
			return credentials.get(0).getName();
		}
		else if (name == null) {
			// we generate a random name
			// in the past we returned the access token as name but this can be a security leak, especially when embedding in a JWT token
			// if you are using an oauth2 token, you likely do not have an actual local identity for the user
			// as such it doesn't matter too much
			synchronized(this) {
				if (name == null) {
					name = UUID.randomUUID().toString().replace("-", "");
				}
			}
		}
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
		return credentials;
	}

	public OAuth2Identity getOAuth2Token() {
		return token;
	}
	public void setOAuth2Token(OAuth2Identity identity) {
		this.token = identity;
	}

	@Override
	public Token refresh() {
		if (token.getRefreshToken() != null && token instanceof OAuth2IdentityWithContext) {
			try {
				Services services = new Services(EAIResourceRepository.getInstance().newExecutionContext(this));
				OAuth2Identity identity = services.refreshToken(
					((OAuth2IdentityWithContext) token).getOauth2Provider(), 
					((OAuth2IdentityWithContext) token).getWebApplication(), 
					token.getRefreshToken(), 
					null);

				JWTToken jwtToken = null;
				if (identity instanceof OAuth2IdentityWithContext) {
					((OAuth2IdentityWithContext) identity).setOauth2Provider(((OAuth2IdentityWithContext) token).getOauth2Provider());
					((OAuth2IdentityWithContext) identity).setWebApplication(((OAuth2IdentityWithContext) token).getWebApplication());
					jwtToken = OAuth2Listener.getJWTToken((OAuth2IdentityWithContext) identity);
				}

				// some providers (like google) only send a refresh token the first time around, any refresh does not return a new refresh token
				// some providers however send a new refresh token every time
				if (identity.getRefreshToken() == null) {
					identity.setRefreshToken(token.getRefreshToken());
				}
				
				OAuth2Token oAuth2Token = new OAuth2Token(identity, realm);
				if (jwtToken != null) {
					oAuth2Token.getCredentials().add(jwtToken);
				}
				return oAuth2Token;
			}
			catch (Exception e) {
				logger.debug("Could not refresh oauth2 token", e);
			}
		}
		return null;
	}

	public void setRealm(String realm) {
		this.realm = realm;
	}

	public void setValidUntil(Date validUntil) {
		this.validUntil = validUntil;
	}

	public void setName(String name) {
		this.name = name;
	}

	public void setCredentials(List<Principal> credentials) {
		this.credentials = credentials;
	}
}
