package be.nabu.eai.module.authentication.oauth2.api;

import javax.jws.WebParam;

import nabu.authentication.oauth2.server.types.OAuth2Identity;
import be.nabu.libs.authentication.api.TokenWithSecret;

public interface OAuth2Authenticator {
	public TokenWithSecret authenticate(@WebParam(name = "oauth2Provider") String oauth2Provider, @WebParam(name = "realm") String realm, @WebParam(name = "credentials") OAuth2Identity credentials);
}
