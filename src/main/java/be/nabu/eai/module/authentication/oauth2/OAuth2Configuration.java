package be.nabu.eai.module.authentication.oauth2;

import java.net.URI;
import java.util.List;

import javax.validation.constraints.NotNull;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import be.nabu.eai.api.InterfaceFilter;
import be.nabu.eai.module.http.artifact.HTTPClientArtifact;
import be.nabu.eai.repository.artifacts.web.WebArtifact;
import be.nabu.eai.repository.jaxb.ArtifactXMLAdapter;
import be.nabu.libs.services.api.DefinedService;

@XmlRootElement(name = "oAuth2")
@XmlType(propOrder = { "clientId", "clientSecret", "scopes", "loginEndpoint", "tokenEndpoint", "apiEndpoint", "httpClient", "webArtifact", "serverPath", "errorPath", "successPath", "authenticatorService", "requireStateToken" })
public class OAuth2Configuration {
	
	private String clientId;
	private String clientSecret;
	private List<String> scopes;
	private URI loginEndpoint;
	private URI tokenEndpoint;
	private URI apiEndpoint;
	private HTTPClientArtifact httpClient;
	private WebArtifact webArtifact;
	private String serverPath;
	private String errorPath, successPath;
	private DefinedService authenticatorService;
	private Boolean requireStateToken;

	@NotNull
	public String getClientId() {
		return clientId;
	}
	public void setClientId(String clientId) {
		this.clientId = clientId;
	}
	
	@NotNull
	public String getClientSecret() {
		return clientSecret;
	}
	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}
	
	@NotNull
	public URI getTokenEndpoint() {
		return tokenEndpoint;
	}
	public void setTokenEndpoint(URI tokenEndpoint) {
		this.tokenEndpoint = tokenEndpoint;
	}
	
	@NotNull
	public List<String> getScopes() {
		return scopes;
	}
	public void setScopes(List<String> scopes) {
		this.scopes = scopes;
	}
	
	@XmlJavaTypeAdapter(value = ArtifactXMLAdapter.class)
	public HTTPClientArtifact getHttpClient() {
		return httpClient;
	}
	public void setHttpClient(HTTPClientArtifact httpClient) {
		this.httpClient = httpClient;
	}
	
	@XmlJavaTypeAdapter(value = ArtifactXMLAdapter.class)
	@NotNull
	public WebArtifact getWebArtifact() {
		return webArtifact;
	}
	public void setWebArtifact(WebArtifact webArtifact) {
		this.webArtifact = webArtifact;
	}
	
	@NotNull
	public URI getLoginEndpoint() {
		return loginEndpoint;
	}
	public void setLoginEndpoint(URI loginEndpoint) {
		this.loginEndpoint = loginEndpoint;
	}
	
	@NotNull
	public URI getApiEndpoint() {
		return apiEndpoint;
	}
	public void setApiEndpoint(URI apiEndpoint) {
		this.apiEndpoint = apiEndpoint;
	}
	
	@NotNull
	public String getServerPath() {
		return serverPath;
	}
	public void setServerPath(String serverPath) {
		this.serverPath = serverPath;
	}
	
	@NotNull
	@XmlJavaTypeAdapter(value = ArtifactXMLAdapter.class)
	@InterfaceFilter(implement = "be.nabu.eai.module.authentication.oauth2.api.OAuth2Authenticator.authenticate")
	public DefinedService getAuthenticatorService() {
		return authenticatorService;
	}
	public void setAuthenticatorService(DefinedService authenticatorService) {
		this.authenticatorService = authenticatorService;
	}
	
	public String getErrorPath() {
		return errorPath;
	}
	public void setErrorPath(String errorPath) {
		this.errorPath = errorPath;
	}
	
	@NotNull
	public String getSuccessPath() {
		return successPath;
	}
	public void setSuccessPath(String successPath) {
		this.successPath = successPath;
	}
	
	public Boolean getRequireStateToken() {
		return requireStateToken;
	}
	public void setRequireStateToken(Boolean requireStateToken) {
		this.requireStateToken = requireStateToken;
	}

}
