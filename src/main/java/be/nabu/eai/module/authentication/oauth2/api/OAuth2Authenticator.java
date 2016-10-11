package be.nabu.eai.module.authentication.oauth2.api;

import javax.jws.WebParam;
import javax.validation.constraints.NotNull;

import nabu.authentication.oauth2.server.types.OAuth2Identity;
import be.nabu.libs.authentication.api.Device;
import be.nabu.libs.authentication.api.TokenWithSecret;

public interface OAuth2Authenticator {
	public TokenWithSecret authenticate(@NotNull @WebParam(name = "oauth2Provider") String oauth2Provider, @NotNull @WebParam(name = "realm") String realm, @NotNull @WebParam(name = "credentials") OAuth2Identity credentials, @NotNull @WebParam(name = "device") Device device);
}
