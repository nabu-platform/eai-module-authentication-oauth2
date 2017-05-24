package be.nabu.eai.module.authentication.oauth2;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Method;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.Key;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import nabu.authentication.oauth2.server.Services;
import nabu.authentication.oauth2.server.Services.GrantType;
import nabu.authentication.oauth2.server.types.OAuth2Identity;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.nabu.eai.module.authentication.oauth2.OAuth2Configuration.TokenResolverType;
import be.nabu.eai.module.authentication.oauth2.api.OAuth2Authenticator;
import be.nabu.eai.module.keystore.KeyStoreArtifact;
import be.nabu.eai.module.web.application.WebApplication;
import be.nabu.eai.repository.EAIResourceRepository;
import be.nabu.eai.repository.util.SystemPrincipal;
import be.nabu.libs.authentication.api.Token;
import be.nabu.libs.authentication.api.TokenWithSecret;
import be.nabu.libs.authentication.impl.DeviceImpl;
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
import be.nabu.libs.http.glue.impl.GlueHTTPUtils;
import be.nabu.libs.http.jwt.JWTBody;
import be.nabu.libs.http.jwt.JWTToken;
import be.nabu.libs.http.jwt.JWTUtils;
import be.nabu.libs.resources.URIUtils;
import be.nabu.libs.services.api.Service;
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
	private static Logger logger = LoggerFactory.getLogger(OAuth2Listener.class);
	private WebApplication application;
	private String path;
	private Service authenticatorService;
	
	public OAuth2Listener(WebApplication application, String path, OAuth2Artifact artifact) {
		this.application = application;
		this.path = path;
		this.artifact = artifact;
		
		this.authenticatorService = artifact.getConfig().getAuthenticatorService();
		// load any configuration that applies
		if (authenticatorService != null) {
			Method method = WebApplication.getMethod(OAuth2Authenticator.class, "authenticate");
			try {
				authenticatorService = application.wrap(artifact.getConfig().getAuthenticatorService(), method);
			}
			catch (IOException e) {
				throw new RuntimeException(e);
			}
		}
	}
	
	private String getFullPath(String childPath) throws IOException {
		// it is already an absolute path
		if (childPath.startsWith("http://") || childPath.startsWith("https://")) {
			return childPath;
		}
		String path = application.getConfiguration().getPath() == null ? "/" : application.getConfiguration().getPath();
		if (this.path != null) {
			path += "/" + this.path;
		}
		if (childPath != null) {
			path += "/" + childPath;
		}
		path = path.replaceAll("[/]{2,}", "/");
		String host = application.getConfiguration().getVirtualHost().getConfiguration().getHost();
		Integer port = application.getConfiguration().getVirtualHost().getConfiguration().getServer().getConfiguration().getPort();
		boolean secure = application.getConfiguration().getVirtualHost().getConfiguration().getServer().getConfiguration().getKeystore() != null;
		return (secure ? "https://" : "http://") + host + (port == null ? "" : ":" + port) + (path.startsWith("/") ? "" : "/") + path;
	}
	
	@Override
	public HTTPResponse handle(HTTPRequest event) {
		try {
			boolean secure = application.getConfiguration().getVirtualHost().getConfiguration().getServer().getConfiguration().getKeystore() != null;
			URI uri = HTTPUtils.getURI(event, secure);
			Map<String, List<String>> queryProperties = URIUtils.getQueryProperties(uri);
			if (queryProperties.containsKey("error") || !queryProperties.containsKey("code")) {
				logger.error("Failed oauth2 login: " + queryProperties);
				if (artifact.getConfiguration().getErrorPath() == null) {
					throw new HTTPException(500, "The login failed: " + queryProperties.get("error") + " - " + queryProperties.get("error_description"));
				}
				return new DefaultHTTPResponse(event, 307, HTTPCodes.getMessage(307),
					new PlainMimeEmptyPart(null, 
						new MimeHeader("Location", getFullPath(artifact.getConfiguration().getErrorPath())),
						new MimeHeader("Content-Length", "0"))
				);
			}
			else {
				boolean mustValidateState = artifact.getConfiguration().getRequireStateToken() != null && artifact.getConfiguration().getRequireStateToken();
				Session session = application.getSessionResolver().getSession(event.getContent().getHeaders());
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
					HTTPRequest request = buildTokenRequest(application, artifact, uri, code, GrantType.AUTHORIZATION, artifact.getConfig().getRedirectUriInTokenRequest(), null);
					logger.debug("Requesting token based on code: " + code);
					HTTPResponse response = newClient.execute(request, null, isSecureTokenEndpoint(application, artifact), true);
					logger.debug("Received token response " + response.getCode() + ": " + response.getMessage());
					if (response.getCode() != 200) {
						throw new HTTPException(500, "Could not retrieve access token based on code: " + response);
					}
					OAuth2IdentityWithContext unmarshalled = getIdentityFromResponse(response);
					unmarshalled.setOauth2Provider(artifact.getId());
					unmarshalled.setWebApplication(application.getId());
					logger.debug("Received access token: " + unmarshalled.getAccessToken() + " which is valid for: " + unmarshalled.getExpiresIn());
					Token token = null;
					List<Header> responseHeaders = new ArrayList<Header>();
					String webApplicationPath = application.getConfiguration().getPath() == null || application.getConfiguration().getPath().isEmpty() ? "/" : application.getConfiguration().getPath();
					// if we don't want to map it to an internal representation of the user, send it back as is
					if (authenticatorService == null) {
						token = new OAuth2Token(unmarshalled, application.getRealm());
						JWTToken jwtToken = getJWTToken(artifact, application.getRealm(), unmarshalled);
						if (jwtToken != null) {
							token.getCredentials().add(jwtToken);
						}
					}
					else {
						OAuth2Authenticator proxy = POJOUtils.newProxy(
							OAuth2Authenticator.class, 
							artifact.getRepository(),
							SystemPrincipal.ROOT,
							authenticatorService
						);
						
						// get the cookies, we want to see if there is a device id yet
						Map<String, List<String>> cookies = HTTPUtils.getCookies(event.getContent().getHeaders());
						boolean isNewDevice = false;
						List<String> cookieValues = cookies.get("Device-" + application.getRealm());
						String deviceId = cookieValues == null || cookieValues.isEmpty() ? null : cookieValues.get(0);
						if (deviceId == null) {
							deviceId = UUID.randomUUID().toString().replace("-", "");
							isNewDevice = true;
						}
						ComplexContent clientConfiguration = application == null ? null : application.getConfigurationFor(artifact.getConfig().getServerPath() == null ? "/" : artifact.getConfig().getServerPath(), artifact.getConfigurationType());
						URI apiEndpoint = artifact.getConfig().getApiEndpoint();
						if (clientConfiguration != null && clientConfiguration.get("apiEndpoint") != null) {
							apiEndpoint = (URI) clientConfiguration.get("apiEndpoint");
						}
						logger.debug("Authenticating user with token using service: " + artifact.getConfiguration().getAuthenticatorService().getId());
						token = proxy.authenticate(application.getId(), artifact.getId(), application.getRealm(), unmarshalled, new DeviceImpl(
							deviceId, 
							GlueHTTPUtils.getUserAgent(event.getContent().getHeaders()), 
							GlueHTTPUtils.getHost(event.getContent().getHeaders())
						), apiEndpoint);
						if (token == null) {
							throw new HTTPException(500, "Login failed");
						}
						logger.debug("Natively authenticated as: " + token.getName());
						// if it's a new device, set a cookie for it
						if (isNewDevice) {
							responseHeaders.add(HTTPUtils.newSetCookieHeader(
								"Device-" + application.getRealm(), 
								deviceId, 
								// Set it to 100 years in the future
								new Date(new Date().getTime() + 1000l*60*60*24*365*100),
								// path
								webApplicationPath, 
								// domain
								null, 
								// secure
								secure,
								// http only
								true
							));
						}
					}
					if (token instanceof TokenWithSecret && ((TokenWithSecret) token).getSecret() != null) {
						responseHeaders.add(HTTPUtils.newSetCookieHeader(
							"Realm-" + application.getRealm(), 
							token.getName() + "/" + ((TokenWithSecret) token).getSecret(), 
							// if there is no valid until in the token, set it to a year
							token.getValidUntil() == null ? new Date(new Date().getTime() + 1000l*60*60*24*365) : token.getValidUntil(),
							// path
							webApplicationPath, 
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
					Session newSession = application.getSessionProvider().newSession();
					// copy & destroy the old one (if any)
					if (session != null) {
						for (String key : session) {
							newSession.set(key, session.get(key));
						}
						session.destroy();
					}
					// set the token in the session
					newSession.set(GlueListener.buildTokenName(application.getRealm()), token);
					// set the correct headers to update the session
					responseHeaders.add(HTTPUtils.newSetCookieHeader(GlueListener.SESSION_COOKIE, newSession.getId(), null, webApplicationPath, null, secure, true));
					responseHeaders.add(new MimeHeader("Location", getFullPath(artifact.getConfiguration().getSuccessPath())));
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

	public static OAuth2IdentityWithContext getIdentityFromResponse(HTTPResponse response) throws IOException, UnsupportedEncodingException, URISyntaxException, ParseException {
		String contentType = MimeUtils.getContentType(response.getContent().getHeaders());
		logger.debug("Received content type: " + contentType);
		OAuth2IdentityWithContext unmarshalled;
		// facebook sends back text/plain...
		if ("text/plain".equals(contentType)) {
			ReadableContainer<ByteBuffer> readable = ((ContentPart) response.getContent()).getReadable();
			try {
				byte [] content = IOUtils.toBytes(readable);
				logger.debug("Received content: " + new String(content, "ASCII"));
				Map<String, List<String>> returnedParameters = URIUtils.getQueryProperties(new URI("?" + new String(content, "ASCII")));
				unmarshalled = new OAuth2IdentityWithContext();
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
			JSONBinding binding = new JSONBinding((ComplexType) BeanResolver.getInstance().resolve(OAuth2IdentityWithContext.class));
			binding.setIgnoreUnknownElements(true);
			logger.debug("Unmarshalling token response");
			if (logger.isTraceEnabled()) {
				logger.trace("Token response: " + new String(IOUtils.toBytes(((ContentPart) response.getContent()).getReadable())));
			}
			ComplexContent unmarshal = binding.unmarshal(IOUtils.toInputStream(((ContentPart) response.getContent()).getReadable()), new Window[0]);
			unmarshalled = TypeUtils.getAsBean(unmarshal, OAuth2IdentityWithContext.class, BeanResolver.getInstance());
		}
		return unmarshalled;
	}
	
	public static boolean isSecureTokenEndpoint(WebApplication webApplication, OAuth2Artifact artifact) throws IOException {
		ComplexContent clientConfiguration = webApplication == null ? null : webApplication.getConfigurationFor(artifact.getConfig().getServerPath() == null ? "/" : artifact.getConfig().getServerPath(), artifact.getConfigurationType());
		URI tokenEndpoint = artifact.getConfiguration().getTokenEndpoint();
		if (clientConfiguration != null && clientConfiguration.get("tokenEndpoint") != null) {
			tokenEndpoint = (URI) clientConfiguration.get("tokenEndpoint");
		}
		return tokenEndpoint.getScheme().equals("https");
	}

	public static HTTPRequest buildTokenRequest(WebApplication webApplication, OAuth2Artifact artifact, URI redirectURI, String code, GrantType grantType, Boolean includeRedirectURI, String resource) throws IOException, UnsupportedEncodingException {
		if (grantType == null) {
			grantType = GrantType.AUTHORIZATION;
		}
		if (includeRedirectURI == null) {
			includeRedirectURI = true;
		}
		String clientId = artifact.getConfig().getClientId();
		String clientSecret = artifact.getConfig().getClientSecret();
		ComplexContent clientConfiguration = webApplication == null ? null : webApplication.getConfigurationFor(artifact.getConfig().getServerPath() == null ? "/" : artifact.getConfig().getServerPath(), artifact.getConfigurationType());
		if (clientConfiguration != null && clientConfiguration.get("clientId") != null) {
			clientId = (String) clientConfiguration.get("clientId");
		}
		if (clientConfiguration != null && clientConfiguration.get("clientSecret") != null) {
			clientSecret = (String) clientConfiguration.get("clientSecret");
		}
		if (clientId == null) {
			throw new IllegalArgumentException("Could not find client id");
		}
		
		// by default we get a code in through a redirect and we send it along
		// for a refresh we have an existing refresh token and we send that
		String requestContent = (grantType == GrantType.AUTHORIZATION ? "code=" : "refresh_token=") + URIUtils.encodeURIComponent(code, false) 
			+ "&client_id=" + URIUtils.encodeURIComponent(clientId, false)
			+ "&client_secret=" + URIUtils.encodeURIComponent(clientSecret, false)
			+ "&grant_type=" + grantType.getGrantName();
		
		// for most providers, the redirect uri is required (e.g. google), but for example for digipolis it is not allowed, you will get exceptions if you send it along
		if (includeRedirectURI) {
			requestContent += "&redirect_uri=" + URIUtils.encodeURI(redirectURI.toString().replaceAll("\\?.*", ""));
		}
		if (resource == null) {
			resource = artifact.getConfiguration().getResource();
		}
		// for microsoft
		if (resource != null) {
			requestContent += "&resource=" + URIUtils.encodeURIComponent(resource);
		}
		logger.debug("Token request content: {}", requestContent);
		HTTPRequest request;
		// facebook uses GET logic
		URI tokenEndpoint = artifact.getConfiguration().getTokenEndpoint();
		if (clientConfiguration != null && clientConfiguration.get("tokenEndpoint") != null) {
			tokenEndpoint = (URI) clientConfiguration.get("tokenEndpoint");
		}
		if (TokenResolverType.GET.equals(artifact.getConfiguration().getTokenResolvingType())) {
			logger.debug("Creating GET request for token request");
			request = new DefaultHTTPRequest("GET", tokenEndpoint.getPath() + (tokenEndpoint.getPath().contains("?") ? "&" : "?") + requestContent, new PlainMimeEmptyPart(null,  
				new MimeHeader("Host", tokenEndpoint.getAuthority()),
				new MimeHeader("Accept", "application/json,application/javascript,application/x-javascript"),
				new MimeHeader("Content-Length", "0")
			));
		}
		// google (et al?) uses POST logic
		else {
			byte[] bytes = requestContent.getBytes("ASCII");
			logger.debug("Creating POST request for token request");
			request = new DefaultHTTPRequest("POST", tokenEndpoint.getPath(), new PlainMimeContentPart(null, IOUtils.wrap(bytes, true), 
				new MimeHeader("Host", tokenEndpoint.getAuthority()),
				new MimeHeader("Content-Type", "application/x-www-form-urlencoded"),
				new MimeHeader("Accept", "application/json,application/javascript,application/x-javascript"),
				new MimeHeader("Content-Length", Integer.valueOf(bytes.length).toString())
			));
		}
		return request;
	}
	
	public static JWTToken getJWTToken(OAuth2IdentityWithContext identity) throws ParseException {
		OAuth2Artifact artifact = (OAuth2Artifact) EAIResourceRepository.getInstance().resolve(identity.getOauth2Provider());
		if (artifact == null) {
			throw new IllegalArgumentException("Can not find oauth2 artifact: " + identity.getOauth2Provider());
		}
		WebApplication webApplication = (WebApplication) EAIResourceRepository.getInstance().resolve(identity.getWebApplication());
		if (webApplication == null) {
			throw new IllegalStateException("Can not find web application: " + identity.getWebApplication());
		}
		return getJWTToken(artifact, webApplication.getRealm(), identity);
	}

	public static JWTToken getJWTToken(OAuth2Artifact artifact, String realm, OAuth2Identity identity) throws ParseException {
		if (artifact.getConfig().getJwtKeyStore() != null && artifact.getConfig().getJwtKeyAlias() != null) {
			KeyStoreArtifact keystore = artifact.getConfig().getJwtKeyStore();
			Key key = null;
			try {
				key = keystore.getKeyStore().getCertificate(artifact.getConfig().getJwtKeyAlias()).getPublicKey();
			}
			catch (Exception e) {
				try {
					key = keystore.getKeyStore().getChain(artifact.getConfig().getJwtKeyAlias())[0].getPublicKey();
				}
				catch (Exception f) {
					logger.info("JWT key alias '" + artifact.getConfig().getJwtKeyAlias() + " does not have a certificate, skipping JWT tokenization for oauth2");
				}
			}
			if (key != null) {
				JWTBody decode = JWTUtils.decode(key, identity.getAccessToken());
				return new JWTToken(decode, realm);
			}
		}
		return null;
	}
}
