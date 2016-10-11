package nabu.authentication.oauth2.server;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.UUID;

import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;
import javax.validation.constraints.NotNull;

import nabu.authentication.oauth2.server.types.OAuth2Identity;
import be.nabu.eai.module.authentication.oauth2.OAuth2Artifact;
import be.nabu.eai.module.authentication.oauth2.OAuth2Listener;
import be.nabu.eai.module.authentication.oauth2.OAuth2Token;
import be.nabu.eai.module.http.server.HTTPServerArtifact;
import be.nabu.eai.module.web.application.WebApplication;
import be.nabu.libs.authentication.api.Token;
import be.nabu.libs.http.HTTPException;
import be.nabu.libs.http.api.HTTPRequest;
import be.nabu.libs.http.api.HTTPResponse;
import be.nabu.libs.http.api.server.Session;
import be.nabu.libs.http.client.DefaultHTTPClient;
import be.nabu.libs.resources.URIUtils;
import be.nabu.libs.services.ServiceRuntime;
import be.nabu.libs.services.api.ExecutionContext;
import be.nabu.utils.mime.impl.FormatException;

@WebService
public class Services {
	
	public static final String OAUTH2_TOKEN = "oauth2Token";
	private ExecutionContext executionContext;
	private ServiceRuntime runtime;

	@WebResult(name = "token")
	public Token toToken(@NotNull @WebParam(name = "credentials") OAuth2Identity identity, @WebParam(name = "realm") String realm) {
		return new OAuth2Token(identity, realm);
	}
	
	@WebResult(name = "credentials")
	public OAuth2Identity refreshToken(@NotNull @WebParam(name = "oAuth2ArtifactId") String oAuth2ArtifactId, @NotNull @WebParam(name = "refreshToken") String refreshToken) throws KeyStoreException, NoSuchAlgorithmException, IOException, URISyntaxException, FormatException, ParseException {
		OAuth2Artifact artifact = executionContext.getServiceContext().getResolver(OAuth2Artifact.class).resolve(oAuth2ArtifactId);
		if (artifact == null) {
			throw new IllegalArgumentException("Can not find oauth2 artifact: " + oAuth2ArtifactId);
		}
		DefaultHTTPClient newClient = nabu.protocols.http.client.Services.newClient(artifact.getConfiguration().getHttpClient());
		HTTPRequest request = OAuth2Listener.buildTokenRequest(artifact, null, refreshToken, GrantType.REFRESH, false);
		HTTPResponse response = newClient.execute(request, null, true, true);
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
		WebApplication webApplication = executionContext.getServiceContext().getResolver(WebApplication.class).resolve(webApplicationId);
		if (webApplication == null) {
			throw new IllegalStateException("Can not find web application: " + webApplicationId);
		}
		else if (webApplication.getConfiguration().getVirtualHost().getConfiguration().getHost() == null) {
			throw new IllegalStateException("To generate the redirect link for oauth2, you need to define the host name in the virtual host");
		}

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
		if (loginEndpoint == null) {
			return null;
		}

		String redirectLink = getRedirectLink(oauth2, webApplication);
		
		String endpoint = loginEndpoint.toString()
			+ (loginEndpoint.getQuery() != null ? "&" : "?") + "client_id=" + URIUtils.encodeURIComponent(oauth2.getConfiguration().getClientId());
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

	private String getRedirectLink(OAuth2Artifact oauth2, WebApplication webApplication) throws IOException {
		HTTPServerArtifact httpServer = webApplication.getConfiguration().getVirtualHost().getConfiguration().getServer();
		if (httpServer == null) {
			throw new IllegalStateException("No http server found");
		}
		Integer port = httpServer.getConfiguration().getPort();
		if (port != null) {
			// if the port is the default port, don't include it
			if (port == 443 && httpServer.getConfiguration().getKeystore() != null) {
				port = null;
			}
			else if (port == 80 && httpServer.getConfiguration().getKeystore() == null) {
				port = null;
			}
		}
		String redirectLink = (httpServer.getConfiguration().getKeystore() != null ? "https" : "http") + "://" + webApplication.getConfiguration().getVirtualHost().getConfiguration().getHost() + (port == null ? "" : ":" + port) + "/";
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
		REFRESH("refresh_token")
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
