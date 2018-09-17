package nabu.authentication.oauth2.server;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.text.ParseException;
import java.util.Date;
import java.util.UUID;

import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;
import javax.validation.constraints.NotNull;

import nabu.authentication.oauth2.server.types.OAuth2Identity;
import be.nabu.eai.module.authentication.oauth2.OAuth2Artifact;
import be.nabu.eai.module.authentication.oauth2.OAuth2IdentityWithContext;
import be.nabu.eai.module.authentication.oauth2.OAuth2Listener;
import be.nabu.eai.module.authentication.oauth2.OAuth2Token;
import be.nabu.eai.module.http.server.HTTPServerArtifact;
import be.nabu.eai.module.web.application.WebApplication;
import be.nabu.eai.module.web.application.WebFragment;
import be.nabu.eai.module.web.application.WebFragmentProvider;
import be.nabu.libs.authentication.api.Token;
import be.nabu.libs.http.HTTPException;
import be.nabu.libs.http.api.HTTPRequest;
import be.nabu.libs.http.api.HTTPResponse;
import be.nabu.libs.http.api.client.HTTPClient;
import be.nabu.libs.http.api.server.Session;
import be.nabu.libs.resources.URIUtils;
import be.nabu.libs.services.ServiceRuntime;
import be.nabu.libs.services.api.ExecutionContext;
import be.nabu.libs.types.api.ComplexContent;
import be.nabu.utils.mime.impl.FormatException;

@WebService
public class Services {
	
	public static final String OAUTH2_TOKEN = "oauth2Token";
	private ExecutionContext executionContext;
	private ServiceRuntime runtime;

	public Services() {
		// auto
	}
	public Services(ExecutionContext context) {
		this.executionContext = context;
	}
	
	@WebResult(name = "token")
	public Token toToken(@NotNull @WebParam(name = "credentials") OAuth2Identity identity, @WebParam(name = "realm") String realm) {
		return new OAuth2Token(identity, realm);
	}

	@WebResult(name = "credentials")
	public OAuth2Identity getCurrentCredentials(@WebParam(name = "token") Token token) throws KeyStoreException, NoSuchAlgorithmException, IOException, URISyntaxException, FormatException, ParseException {
		if (token == null) {
			token = executionContext.getSecurityContext().getToken();
		}
		if (token != null) {
			OAuth2Identity identity = null;
			if (token instanceof OAuth2Token) {
				identity = ((OAuth2Token) token).getOAuth2Token();
			}
			else if (token.getCredentials() != null) {
				for (Principal principal : token.getCredentials()) {
					if (principal instanceof OAuth2Token) {
						identity = ((OAuth2Token) principal).getOAuth2Token();
					}
				}
			}
			if (identity != null) {
				// if we have some context and a refresh token, update it if necessary
				if (identity instanceof OAuth2IdentityWithContext && identity.getRefreshToken() != null) {
					// if it expires within 5 minutes and has a refresh, trigger automatically
					if (((OAuth2IdentityWithContext) identity).getExpired().getTime() - new Date().getTime() < 300000) {
						OAuth2Identity refreshed = refreshToken(
							((OAuth2IdentityWithContext) identity).getOauth2Provider(),
							((OAuth2IdentityWithContext) identity).getWebApplication(),
							identity.getRefreshToken(),
							null
						);
						if (refreshed != null) {
							identity.setAccessToken(refreshed.getAccessToken());
							identity.setExpiresIn(refreshed.getExpiresIn());
							identity.setRefreshToken(refreshed.getRefreshToken());
							identity.setTokenType(refreshed.getTokenType());
							((OAuth2IdentityWithContext) identity).recreate();
						}
					}
				}
				return identity;
			}
		}
		return null;
	}
	
	/**
	 * For microsoft you can do this:
	 * - get token for the discovery resource, allowing you to discover API's
	 * - use refresh token of discovery resource to get a new token for target API using the newly discovered resource
	 */
	@WebResult(name = "credentials")
	public OAuth2Identity refreshToken(@NotNull @WebParam(name = "oAuth2ArtifactId") String oAuth2ArtifactId, @NotNull @WebParam(name = "webApplicationId") String webApplicationId, @NotNull @WebParam(name = "refreshToken") String refreshToken, @WebParam(name = "resource") String resource) throws KeyStoreException, NoSuchAlgorithmException, IOException, URISyntaxException, FormatException, ParseException {
		OAuth2Artifact artifact = executionContext.getServiceContext().getResolver(OAuth2Artifact.class).resolve(oAuth2ArtifactId);
		if (artifact == null) {
			throw new IllegalArgumentException("Can not find oauth2 artifact: " + oAuth2ArtifactId);
		}
		WebApplication webApplication = executionContext.getServiceContext().getResolver(WebApplication.class).resolve(webApplicationId);
		if (webApplication == null) {
			throw new IllegalStateException("Can not find web application: " + webApplicationId);
		}
		HTTPClient newClient = nabu.protocols.http.client.Services.newClient(artifact.getConfiguration().getHttpClient());
		HTTPRequest request = OAuth2Listener.buildTokenRequest(webApplication, artifact, null, refreshToken, GrantType.REFRESH, false, resource, null, null);
		HTTPResponse response = newClient.execute(request, null, OAuth2Listener.isSecureTokenEndpoint(webApplication, artifact), true);
		if (response.getCode() != 200) {
			throw new HTTPException(500, "Could not retrieve access token based on code: " + response);
		}
		return OAuth2Listener.getIdentityFromResponse(response);
	}
	
	// this is a simple way to get a token if you have the username and password
	// this is the oauth2 equivalent of basic auth
	@WebResult(name = "credentials")
	public OAuth2Identity newPasswordToken(@NotNull @WebParam(name = "oAuth2ArtifactId") String oAuth2ArtifactId, @NotNull @WebParam(name = "username") String username, @NotNull @WebParam(name = "password") String password, @WebParam(name = "resource") String resource) throws UnsupportedEncodingException, IOException, URISyntaxException, ParseException, KeyStoreException, NoSuchAlgorithmException, FormatException {
		OAuth2Artifact artifact = executionContext.getServiceContext().getResolver(OAuth2Artifact.class).resolve(oAuth2ArtifactId);
		if (artifact == null) {
			throw new IllegalArgumentException("Can not find oauth2 artifact: " + oAuth2ArtifactId);
		}
		HTTPClient newClient = nabu.protocols.http.client.Services.newClient(artifact.getConfiguration().getHttpClient());
		HTTPRequest request = OAuth2Listener.buildTokenRequest(null, artifact, null, null, GrantType.PASSWORD, false, resource, username, password);
		HTTPResponse response = newClient.execute(request, null, OAuth2Listener.isSecureTokenEndpoint(null, artifact), true);
		if (response.getCode() != 200) {
			throw new HTTPException(500, "Could not retrieve access token based on code: " + response);
		}
		return OAuth2Listener.getIdentityFromResponse(response);
	}
	
	// client token is to access your own resources without user interaction
	// presumably the initial creation involved user interaction so the resource is bound to the user and yourself
	// if you need offline access, it can be enough to use client credentials rather then refresh token for client credentials
	@WebResult(name = "credentials")
	public OAuth2Identity newClientToken(@NotNull @WebParam(name = "oAuth2ArtifactId") String oAuth2ArtifactId, @NotNull @WebParam(name = "webApplicationId") String webApplicationId, @WebParam(name = "resource") String resource) throws UnsupportedEncodingException, IOException, URISyntaxException, ParseException, KeyStoreException, NoSuchAlgorithmException, FormatException {
		OAuth2Artifact artifact = executionContext.getServiceContext().getResolver(OAuth2Artifact.class).resolve(oAuth2ArtifactId);
		if (artifact == null) {
			throw new IllegalArgumentException("Can not find oauth2 artifact: " + oAuth2ArtifactId);
		}
		WebApplication webApplication = executionContext.getServiceContext().getResolver(WebApplication.class).resolve(webApplicationId);
		if (webApplication == null) {
			throw new IllegalStateException("Can not find web application: " + webApplicationId);
		}
		HTTPClient newClient = nabu.protocols.http.client.Services.newClient(artifact.getConfiguration().getHttpClient());
		HTTPRequest request = OAuth2Listener.buildTokenRequest(webApplication, artifact, null, null, GrantType.CLIENT, false, resource, null, null);
		HTTPResponse response = newClient.execute(request, null, OAuth2Listener.isSecureTokenEndpoint(null, artifact), true);
		if (response.getCode() != 200) {
			throw new HTTPException(500, "Could not retrieve access token based on code: " + response);
		}
		return OAuth2Listener.getIdentityFromResponse(response);
	}
	
	@WebResult(name = "link")
	public String getRedirectLink(@NotNull @WebParam(name = "oAuth2ArtifactId") String oAuth2ArtifactId, @NotNull @WebParam(name = "webApplicationId") String webApplicationId, @WebParam(name = "accessType") AccessType accessType, @WebParam(name = "approvalPrompt") Boolean approvalPrompt) throws IOException {
		OAuth2Artifact oauth2 = executionContext.getServiceContext().getResolver(OAuth2Artifact.class).resolve(oAuth2ArtifactId);
		if (oauth2 == null) {
			throw new IllegalArgumentException("Can not find oauth2 artifact: " + oAuth2ArtifactId);
		}
		if (approvalPrompt == null) {
			approvalPrompt = oauth2.getConfig().isRequireApprovalPrompt();
		}
		WebApplication webApplication = executionContext.getServiceContext().getResolver(WebApplication.class).resolve(webApplicationId);
		if (webApplication == null) {
			throw new IllegalStateException("Can not find web application: " + webApplicationId);
		}
		if (!isIncluded(oauth2, webApplication)) {
			throw new IllegalStateException("The oauth2 provider '" + oAuth2ArtifactId + "' is not included in the web application: " + webApplicationId);
		}
		if (webApplication.getConfiguration().getVirtualHost().getConfiguration().getHost() == null) {
			throw new IllegalStateException("To generate the redirect link for oauth2, you need to define the host name in the virtual host");
		}
		ComplexContent configuration = webApplication.getConfigurationFor(oauth2.getConfig().getServerPath() == null ? "/" : oauth2.getConfig().getServerPath(), oauth2.getConfigurationType());
		StringBuilder builder = new StringBuilder();
		if (oauth2.getConfiguration().getScopes() != null) {
			for (String scope : oauth2.getConfiguration().getScopes()) {
				if (!builder.toString().isEmpty()) {
					builder.append(" ");
				}
				builder.append(scope);
			}
		}
		URI loginEndpoint = oauth2.getConfiguration().getLoginEndpoint();
		if (configuration != null && configuration.get("loginEndpoint") != null) {
			loginEndpoint = (URI) configuration.get("loginEndpoint");
		}
		if (loginEndpoint == null) {
			return null;
		}

		URI configuredRedirectLink = oauth2.getConfiguration().getRedirectLink();
		if (configuration != null && configuration.get("redirectLink") != null) {
			configuredRedirectLink = (URI) configuration.get("redirectLink");
		}
		String redirectLink = configuredRedirectLink == null ? getRedirectLink(oauth2, webApplication) : configuredRedirectLink.toString();
		
		String clientId = oauth2.getConfiguration().getClientId();
		if (configuration != null && configuration.get("clientId") != null) {
			clientId = (String) configuration.get("clientId");
		}
		if (clientId == null) {
			throw new IllegalStateException("Can not find client id");
		}
		String endpoint = loginEndpoint.toString()
			+ (loginEndpoint.getQuery() != null ? "&" : "?") + "client_id=" + URIUtils.encodeURIComponent(clientId);
		if (!builder.toString().trim().isEmpty()) {
			endpoint += "&scope=" + URIUtils.encodeURIComponent(builder.toString());
		}
		endpoint += "&redirect_uri=" + URIUtils.encodeURI(redirectLink)
			+ "&response_type=code";
		
		// This is currently only valid for google as far as I know
		if (accessType != null && AccessType.OFFLINE.equals(accessType)) {
			if (approvalPrompt == null || approvalPrompt) {
				endpoint += "&approval_prompt=force";
			}
			endpoint += "&access_type=offline";
		}
		else if (approvalPrompt == null || approvalPrompt) {
			// this prevents google from prompting every time
			endpoint += "&approval_prompt=auto";
		}
		
		if (runtime.getContext().get("session") != null) {
			// you can have multiple oauth2 modules in one call, they all need to use the same token 
			String oauth2Token = (String) ((Session) runtime.getContext().get("session")).get(OAUTH2_TOKEN);
			if (oauth2Token == null) {
				oauth2Token = UUID.randomUUID().toString().replace("-", "");
				((Session) runtime.getContext().get("session")).set(OAUTH2_TOKEN, oauth2Token);
			}
			endpoint += "&state=" + oauth2Token;
		}
		return endpoint;
	}

	private boolean isIncluded(OAuth2Artifact oauth2, WebFragmentProvider provider) {
		if (provider.getWebFragments() != null) {
			for (WebFragment fragment : provider.getWebFragments()) {
				if (oauth2.equals(fragment)) {
					return true;
				}
				else if (fragment instanceof WebFragmentProvider) {
					boolean result = isIncluded(oauth2, (WebFragmentProvider) fragment);
					if (result) {
						return true;
					}
				}
			}
		}
		return false;
	}
	
	private String getRedirectLink(OAuth2Artifact oauth2, WebApplication webApplication) throws IOException {
		HTTPServerArtifact httpServer = webApplication.getConfiguration().getVirtualHost().getConfiguration().getServer();
		if (httpServer == null) {
			throw new IllegalStateException("No http server found");
		}
		Integer port = httpServer.getConfig().isProxied() ? httpServer.getConfig().getProxyPort() : httpServer.getConfiguration().getPort();
		if (port != null) {
			// if the port is the default port, don't include it
			if (port == 443 && httpServer.getConfiguration().getKeystore() != null) {
				port = null;
			}
			else if (port == 80 && httpServer.getConfiguration().getKeystore() == null) {
				port = null;
			}
		}
		boolean secure = httpServer.getConfig().isProxied() ? httpServer.getConfig().isProxySecure() : httpServer.getConfiguration().getKeystore() != null;
		String redirectLink = (secure ? "https" : "http") + "://" + webApplication.getConfiguration().getVirtualHost().getConfiguration().getHost() + (port == null ? "" : ":" + port) + "/";
		if (webApplication.getConfiguration().getPath() != null && !webApplication.getConfiguration().getPath().isEmpty() && !webApplication.getConfiguration().getPath().equals("/")) {
			redirectLink += webApplication.getConfiguration().getPath().replaceFirst("^[/]+", "");
		}
		if (oauth2.getRelativePath() != null) {
			if (!redirectLink.endsWith("/")) {
				redirectLink += "/";
			}
			redirectLink += oauth2.getRelativePath().replaceFirst("^[/]+", "");
		}
		return redirectLink;
	}
	
	public enum AccessType {
		ONLINE,
		OFFLINE
	}
	
	public enum GrantType {
		AUTHORIZATION("authorization_code"),
		REFRESH("refresh_token"),
		PASSWORD("password"),
		CLIENT("client_credentials")
		;
		private String grantName;

		private GrantType(String grantName) {
			this.grantName = grantName;
		}
		public String getGrantName() {
			return grantName;
		}
	}
}
