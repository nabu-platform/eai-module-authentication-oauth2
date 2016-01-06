package nabu.utils;

import java.io.IOException;
import java.net.URI;
import java.util.UUID;

import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;
import javax.validation.constraints.NotNull;

import be.nabu.eai.module.authentication.oauth2.OAuth2Artifact;
import be.nabu.eai.repository.artifacts.http.DefinedHTTPServer;
import be.nabu.eai.repository.artifacts.web.WebArtifact;
import be.nabu.libs.http.api.server.Session;
import be.nabu.libs.resources.URIUtils;
import be.nabu.libs.services.ServiceRuntime;
import be.nabu.libs.services.api.ExecutionContext;

@WebService
public class Oauth2 {
	
	public static final String OAUTH2_TOKEN = "oauth2Token";
	private ExecutionContext executionContext;
	private ServiceRuntime runtime;
	
	@WebResult(name = "link")
	public String getRedirectLink(@NotNull @WebParam(name = "oAuth2ArtifactId") String oAuth2ArtifactId) throws IOException {
		OAuth2Artifact oauth2 = executionContext.getServiceContext().getResolver(OAuth2Artifact.class).resolve(oAuth2ArtifactId);
		if (oauth2 == null) {
			throw new IllegalArgumentException("Can not find oauth2 artifact: " + oAuth2ArtifactId);
		}
		WebArtifact webArtifact = oauth2.getConfiguration().getWebArtifact();
		if (webArtifact == null) {
			throw new IllegalStateException("No web artifact found");
		}
		else if (webArtifact.getConfiguration().getVirtualHost().getConfiguration().getHost() == null) {
			throw new IllegalStateException("To generate the redirect link for oauth2, you need to define the host name in the virtual host");
		}
		DefinedHTTPServer httpServer = webArtifact.getConfiguration().getVirtualHost().getConfiguration().getServer();
		if (httpServer == null) {
			throw new IllegalStateException("No http server found");
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
		
		String redirectLink = (httpServer.getConfiguration().getKeystore() != null ? "https" : "http") + "://" + webArtifact.getConfiguration().getVirtualHost().getConfiguration().getHost() + ":" + httpServer.getConfiguration().getPort() + "/";
		if (webArtifact.getConfiguration().getPath() != null && !webArtifact.getConfiguration().getPath().isEmpty() && !webArtifact.getConfiguration().getPath().equals("/")) {
			redirectLink += webArtifact.getConfiguration().getPath().replaceFirst("^[/]+", "");
		}
		if (oauth2.getRelativePath() != null) {
			if (!redirectLink.endsWith("/")) {
				redirectLink += "/";
			}
			redirectLink += oauth2.getRelativePath().replaceFirst("^[/]+", "");
		}

		String endpoint = loginEndpoint.toString()
			+ "?client_id=" + URIUtils.encodeURIComponent(oauth2.getConfiguration().getClientId())
			+ "&scope=" + URIUtils.encodeURIComponent(builder.toString())
			+ "&redirect_uri=" + URIUtils.encodeURI(redirectLink)
			+ "&response_type=code"
			+ "&approval_prompt=auto";
		
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
	
}
