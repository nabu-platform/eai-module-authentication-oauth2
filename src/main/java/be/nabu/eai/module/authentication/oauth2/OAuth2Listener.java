package be.nabu.eai.module.authentication.oauth2;

import java.net.URI;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import nabu.authentication.oauth2.Services;
import nabu.authentication.oauth2.types.OAuth2Token;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.nabu.eai.module.authentication.oauth2.OAuth2Configuration.TokenResolverType;
import be.nabu.eai.module.authentication.oauth2.api.OAuth2Authenticator;
import be.nabu.eai.repository.util.SystemPrincipal;
import be.nabu.libs.authentication.api.TokenWithSecret;
import be.nabu.libs.events.api.EventHandler;
import be.nabu.libs.http.HTTPCodes;
import be.nabu.libs.http.HTTPException;
import be.nabu.libs.http.api.HTTPRequest;
import be.nabu.libs.http.api.HTTPResponse;
import be.nabu.libs.http.api.server.Session;
import be.nabu.libs.http.client.DefaultHTTPClient;
import be.nabu.libs.http.core.DefaultHTTPRequest;
import be.nabu.libs.http.core.DefaultHTTPResponse;
import be.nabu.libs.http.core.HTTPUtils;
import be.nabu.libs.http.glue.GlueListener;
import be.nabu.libs.resources.URIUtils;
import be.nabu.libs.services.pojo.POJOUtils;
import be.nabu.libs.types.TypeUtils;
import be.nabu.libs.types.api.ComplexContent;
import be.nabu.libs.types.api.ComplexType;
import be.nabu.libs.types.binding.api.Window;
import be.nabu.libs.types.binding.json.JSONBinding;
import be.nabu.libs.types.java.BeanResolver;
import be.nabu.utils.io.IOUtils;
import be.nabu.utils.io.api.ByteBuffer;
import be.nabu.utils.io.api.ReadableContainer;
import be.nabu.utils.mime.api.ContentPart;
import be.nabu.utils.mime.api.Header;
import be.nabu.utils.mime.impl.MimeHeader;
import be.nabu.utils.mime.impl.MimeUtils;
import be.nabu.utils.mime.impl.PlainMimeContentPart;
import be.nabu.utils.mime.impl.PlainMimeEmptyPart;

public class OAuth2Listener implements EventHandler<HTTPRequest, HTTPResponse> {

	private OAuth2Artifact artifact;
	private Logger logger = LoggerFactory.getLogger(getClass());

	public OAuth2Listener(OAuth2Artifact artifact) {
		this.artifact = artifact;
	}
	
	@Override
	public HTTPResponse handle(HTTPRequest event) {
		try {
			boolean secure = artifact.getConfiguration().getWebArtifact().getConfiguration().getVirtualHost().getConfiguration().getServer().getConfiguration().getKeystore() != null;
			URI uri = HTTPUtils.getURI(event, secure);
			Map<String, List<String>> queryProperties = URIUtils.getQueryProperties(uri);
			if (queryProperties.containsKey("error") || !queryProperties.containsKey("code")) {
				logger.error("Failed oauth2 login: " + queryProperties);
				if (artifact.getConfiguration().getErrorPath() == null) {
					throw new HTTPException(500, "The login failed: " + queryProperties.get("error") + " - " + queryProperties.get("error_description"));
				}
				return new DefaultHTTPResponse(event, 307, HTTPCodes.getMessage(307),
					new PlainMimeEmptyPart(null, new MimeHeader("Location", artifact.getConfiguration().getErrorPath()))
				);
			}
			else {
				boolean mustValidateState = artifact.getConfiguration().getRequireStateToken() != null && artifact.getConfiguration().getRequireStateToken();
				Session session = artifact.getConfiguration().getWebArtifact().getSessionResolver().getSession(event.getContent().getHeaders());
				if (session != null) {
					String oauth2Token = (String) session.get(Services.OAUTH2_TOKEN);
					// check the token
					if (oauth2Token != null) {
						logger.debug("Checking csrf token for oauth2: " + oauth2Token);
						if (!queryProperties.containsKey("state")) {
							throw new HTTPException(400, "No csrf token found for oauth2 authentication");
						}
						else if (!oauth2Token.equals(queryProperties.get("state").get(0))) {
							throw new HTTPException(400, "Possible csrf attack, the oauth2 token '" + oauth2Token + "' does not match the return state '" + queryProperties.get("state").get(0) + "'");
						}
					}
					else if (mustValidateState) {
						throw new HTTPException(400, "No oauth2 state token found in the session, can not validate");
					}
				}
				else if (mustValidateState) {
					throw new HTTPException(400, "No session found, can not validate oauth2 state token");
				}
				logger.debug("OAuth2 login successful, code retrieved");
				String code = queryProperties.get("code").get(0);
				DefaultHTTPClient newClient = nabu.protocols.http.client.Services.newClient(artifact.getConfiguration().getHttpClient());
				try {
					String requestContent = "code=" + URIUtils.encodeURIComponent(code) 
						+ "&client_id=" + URIUtils.encodeURIComponent(artifact.getConfiguration().getClientId())
						+ "&client_secret=" + URIUtils.encodeURIComponent(artifact.getConfiguration().getClientSecret())
						+ "&redirect_uri=" + URIUtils.encodeURI(uri.toString().replaceAll("\\?.*", ""))
						+ "&grant_type=authorization_code";
					HTTPRequest request;
					// facebook uses GET logic
					if (TokenResolverType.GET.equals(artifact.getConfiguration().getTokenResolvingType())) {
						logger.debug("Creating GET request for token request");
						request = new DefaultHTTPRequest("GET", artifact.getConfiguration().getTokenEndpoint().getPath() + "?" + requestContent, new PlainMimeEmptyPart(null,  
							new MimeHeader("Host", artifact.getConfiguration().getTokenEndpoint().getAuthority()),
							new MimeHeader("Accept", "application/json,application/javascript,application/x-javascript"),
							new MimeHeader("Content-Length", "0")
						));
					}
					// google (et al?) uses POST logic
					else {
						byte[] bytes = requestContent.getBytes("ASCII");
						logger.debug("Creating POST request for token request");
						request = new DefaultHTTPRequest("POST", artifact.getConfiguration().getTokenEndpoint().getPath(), new PlainMimeContentPart(null, IOUtils.wrap(bytes, true), 
							new MimeHeader("Host", artifact.getConfiguration().getTokenEndpoint().getAuthority()),
							new MimeHeader("Content-Type", "application/x-www-form-urlencoded"),
							new MimeHeader("Accept", "application/json,application/javascript,application/x-javascript"),
							new MimeHeader("Content-Length", Integer.valueOf(bytes.length).toString())
						));
					}
					logger.debug("Requesting token based on code: " + code);
					HTTPResponse response = newClient.execute(request, null, true, true);
					logger.debug("Received token response " + response.getCode() + ": " + response.getMessage());
					if (response.getCode() != 200) {
						throw new HTTPException(500, "Could not retrieve access token based on code: " + response);
					}
					String contentType = MimeUtils.getContentType(response.getContent().getHeaders());
					logger.debug("Received content type: " + contentType);
					OAuth2Token unmarshalled;
					// facebook sends back text/plain...
					if ("text/plain".equals(contentType)) {
						ReadableContainer<ByteBuffer> readable = ((ContentPart) response.getContent()).getReadable();
						try {
							byte [] content = IOUtils.toBytes(readable);
							logger.debug("Received content: " + new String(content, "ASCII"));
							Map<String, List<String>> returnedParameters = URIUtils.getQueryProperties(new URI("?" + new String(content, "ASCII")));
							unmarshalled = new OAuth2Token();
							if (returnedParameters.get("access_token") == null || returnedParameters.get("access_token").isEmpty()) {
								throw new HTTPException(500, "Could not find access_token in the returned content: " + new String(content));
							}
							unmarshalled.setAccessToken(returnedParameters.get("access_token").get(0));
							if (returnedParameters.get("expires") != null && !returnedParameters.get("expires").isEmpty()) {
								unmarshalled.setExpiresIn(Integer.parseInt(returnedParameters.get("expires").get(0)));
							}
						}
						finally {
							readable.close();
						}
					}
					// normally it should be json though
					else {
						JSONBinding binding = new JSONBinding((ComplexType) BeanResolver.getInstance().resolve(OAuth2Token.class));
						binding.setIgnoreUnknownElements(true);
						logger.debug("Unmarshalling token response");
						if (logger.isTraceEnabled()) {
							logger.trace("Token response: " + new String(IOUtils.toBytes(((ContentPart) response.getContent()).getReadable())));
						}
						ComplexContent unmarshal = binding.unmarshal(IOUtils.toInputStream(((ContentPart) response.getContent()).getReadable()), new Window[0]);
						unmarshalled = TypeUtils.getAsBean(unmarshal, OAuth2Token.class, BeanResolver.getInstance());
					}
					logger.debug("Received access token: " + unmarshalled.getAccessToken() + " which is valid for: " + unmarshalled.getExpiresIn());
					OAuth2Authenticator proxy = POJOUtils.newProxy(
						OAuth2Authenticator.class, 
						artifact.getRepository(),
						SystemPrincipal.ROOT,
						artifact.getConfiguration().getAuthenticatorService() 
					);
					logger.debug("Authenticating user with token using service: " + artifact.getConfiguration().getAuthenticatorService().getId());
					TokenWithSecret token = proxy.authenticate(artifact.getId(), artifact.getConfiguration().getWebArtifact().getRealm(), unmarshalled);
					if (token == null) {
						throw new HTTPException(500, "Login failed");
					}
					logger.debug("Authenticated as: " + token.getName());
					List<Header> responseHeaders = new ArrayList<Header>();
					String webArtifactPath = artifact.getConfiguration().getWebArtifact().getConfiguration().getPath() == null || artifact.getConfiguration().getWebArtifact().getConfiguration().getPath().isEmpty() ? "/" : artifact.getConfiguration().getWebArtifact().getConfiguration().getPath();
					if (token.getSecret() != null) {
						responseHeaders.add(HTTPUtils.newSetCookieHeader(
							"Realm-" + artifact.getConfiguration().getWebArtifact().getRealm(), 
							token.getName() + "/" + ((TokenWithSecret) token).getSecret(), 
							// if there is no valid until in the token, set it to a year
							token.getValidUntil() == null ? new Date(new Date().getTime() + 1000l*60*60*24*365) : token.getValidUntil(),
							// path
							webArtifactPath, 
							// domain
							null, 
							// secure
							secure,
							// http only
							true
						));
					}
					logger.debug("Creating new session");
					// create a new session
					Session newSession = artifact.getConfiguration().getWebArtifact().getSessionProvider().newSession();
					// copy & destroy the old one (if any)
					if (session != null) {
						for (String key : session) {
							newSession.set(key, session.get(key));
						}
						session.destroy();
					}
					// set the token in the session
					newSession.set(GlueListener.buildTokenName(artifact.getConfiguration().getWebArtifact().getRealm()), token);
					// set the correct headers to update the session
					responseHeaders.add(HTTPUtils.newSetCookieHeader(GlueListener.SESSION_COOKIE, newSession.getId(), null, webArtifactPath, null, secure, true));
					responseHeaders.add(new MimeHeader("Location", artifact.getConfiguration().getSuccessPath()));
					responseHeaders.add(new MimeHeader("Content-Length", "0"));
					logger.debug("Sending back 307");
					return new DefaultHTTPResponse(event, 307, HTTPCodes.getMessage(307),
						new PlainMimeEmptyPart(null, responseHeaders.toArray(new Header[responseHeaders.size()]))
					);
				}
				finally {
					newClient.getConnectionHandler().close();
				}
			}
		}
		catch (HTTPException e) {
			logger.error("Failed oauth2 authentication", e);
			throw e;
		}
		catch (Exception e) {
			logger.error("Failed oauth2 authentication", e);
			throw new HTTPException(500, e);
		}
		catch(Error e) {
			logger.error("Failed oauth2 authentication", e);
			throw e;
		}
	}

}
