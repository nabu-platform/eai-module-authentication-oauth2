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

import java.net.URI;
import java.util.List;

import javax.validation.constraints.NotNull;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import be.nabu.eai.api.Advanced;
import be.nabu.eai.api.Comment;
import be.nabu.eai.api.EnvironmentSpecific;
import be.nabu.eai.api.InterfaceFilter;
import be.nabu.eai.module.http.client.HTTPClientArtifact;
import be.nabu.eai.module.keystore.KeyStoreArtifact;
import be.nabu.eai.repository.jaxb.ArtifactXMLAdapter;
import be.nabu.libs.services.api.DefinedService;

@XmlRootElement(name = "oAuth2")
@XmlType(propOrder = { "clientId", "clientSecret", "scopes", "loginEndpoint", "tokenEndpoint", "apiEndpoint", "resource", "httpClient", "serverPath", "errorPath", "successPath", "authenticatorService", "requireStateToken", "tokenResolvingType", "redirectUriInTokenRequest", "jwtKeyStore", "jwtKeyAlias", "jwtUseOriginalRealm", "redirectLink", "multipleEnvironments", "requireApprovalPrompt", "ignoreAccessType" })
public class OAuth2Configuration {
	
	public enum TokenResolverType {
		POST,
		GET
	}
	
	private String clientId;
	private String clientSecret;
	/**
	 * Microsoft requires a resource to be passed along in the code-to-token part of the request (https://dev.onedrive.com/auth/aad_oauth.htm)
	 * For example: https://api.office.com/discovery/
	 */
	private String resource;
	private List<String> scopes;
	private URI loginEndpoint;
	private URI tokenEndpoint;
	private URI apiEndpoint;
	private URI redirectLink;
	private HTTPClientArtifact httpClient;
	private String serverPath;
	private String errorPath, successPath;
	private DefinedService authenticatorService;
	private Boolean requireStateToken;
	private TokenResolverType tokenResolvingType;
	private Boolean redirectUriInTokenRequest = true;

	private String jwtKeyAlias;
	private KeyStoreArtifact jwtKeyStore;
	private boolean jwtUseOriginalRealm, multipleEnvironments;
	private boolean requireApprovalPrompt, ignoreAccessType;
	
	@EnvironmentSpecific
	public String getClientId() {
		return clientId;
	}
	public void setClientId(String clientId) {
		this.clientId = clientId;
	}
	
	@EnvironmentSpecific
	public String getClientSecret() {
		return clientSecret;
	}
	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}
	
	public String getResource() {
		return resource;
	}
	public void setResource(String resource) {
		this.resource = resource;
	}
	
	@EnvironmentSpecific
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
	
	@EnvironmentSpecific
	@XmlJavaTypeAdapter(value = ArtifactXMLAdapter.class)
	public HTTPClientArtifact getHttpClient() {
		return httpClient;
	}
	public void setHttpClient(HTTPClientArtifact httpClient) {
		this.httpClient = httpClient;
	}
	
	@EnvironmentSpecific
	public URI getLoginEndpoint() {
		return loginEndpoint;
	}
	public void setLoginEndpoint(URI loginEndpoint) {
		this.loginEndpoint = loginEndpoint;
	}
	
	@EnvironmentSpecific
	public URI getApiEndpoint() {
		return apiEndpoint;
	}
	public void setApiEndpoint(URI apiEndpoint) {
		this.apiEndpoint = apiEndpoint;
	}
	
	public String getServerPath() {
		return serverPath;
	}
	public void setServerPath(String serverPath) {
		this.serverPath = serverPath;
	}
	
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
	
	public TokenResolverType getTokenResolvingType() {
		return tokenResolvingType;
	}
	public void setTokenResolvingType(TokenResolverType tokenResolvingType) {
		this.tokenResolvingType = tokenResolvingType;
	}
	
	public Boolean getRedirectUriInTokenRequest() {
		return redirectUriInTokenRequest;
	}
	public void setRedirectUriInTokenRequest(Boolean redirectUriInTokenRequest) {
		this.redirectUriInTokenRequest = redirectUriInTokenRequest;
	}

	@Advanced
	@EnvironmentSpecific
	public String getJwtKeyAlias() {
		return jwtKeyAlias;
	}
	public void setJwtKeyAlias(String jwtKeyAlias) {
		this.jwtKeyAlias = jwtKeyAlias;
	}
	
	@Advanced
	@EnvironmentSpecific
	@XmlJavaTypeAdapter(value = ArtifactXMLAdapter.class)
	public KeyStoreArtifact getJwtKeyStore() {
		return jwtKeyStore;
	}
	public void setJwtKeyStore(KeyStoreArtifact jwtKeyStore) {
		this.jwtKeyStore = jwtKeyStore;
	}
	
	@Advanced
	public boolean isJwtUseOriginalRealm() {
		return jwtUseOriginalRealm;
	}
	public void setJwtUseOriginalRealm(boolean jwtUseOriginalRealm) {
		this.jwtUseOriginalRealm = jwtUseOriginalRealm;
	}
	
	@Advanced
	@EnvironmentSpecific
	@Comment(title = "You can override the automatically generated redirect link here, this can be useful for example in environments with reverse proxies")
	public URI getRedirectLink() {
		return redirectLink;
	}
	public void setRedirectLink(URI redirectLink) {
		this.redirectLink = redirectLink;
	}
	
	@Advanced
	@Comment(title = "Most providers (e.g. facebook, google,...) have only one environment: their prd. However custom providers might have multiple, set this to enable that")
	public boolean isMultipleEnvironments() {
		return multipleEnvironments;
	}
	public void setMultipleEnvironments(boolean multipleEnvironments) {
		this.multipleEnvironments = multipleEnvironments;
	}
	
	@Advanced
	@Comment(title = "Some providers require this boolean toggled for redirect links (e.g. google). You can override the value by explicitly setting it when generating a redirect link")
	public boolean isRequireApprovalPrompt() {
		return requireApprovalPrompt;
	}
	public void setRequireApprovalPrompt(boolean requireApprovalPrompt) {
		this.requireApprovalPrompt = requireApprovalPrompt;
	}
	
	@Advanced
	@Comment(title = "Some providers do not support an access type parameter")
	public boolean isIgnoreAccessType() {
		return ignoreAccessType;
	}
	public void setIgnoreAccessType(boolean ignoreAccessType) {
		this.ignoreAccessType = ignoreAccessType;
	}

	
}
