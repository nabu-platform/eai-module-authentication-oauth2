package be.nabu.eai.module.authentication.oauth2;

import java.util.Date;

import javax.xml.bind.annotation.XmlElement;

import nabu.authentication.oauth2.server.types.OAuth2Identity;

public class OAuth2IdentityWithContext extends OAuth2Identity {
	private String oauth2Provider, webApplication;
	private Date created = new Date(), expired;

	@XmlElement(name = "oauth2_provider")
	public String getOauth2Provider() {
		return oauth2Provider;
	}
	public void setOauth2Provider(String oauth2Provider) {
		this.oauth2Provider = oauth2Provider;
	}
	
	@XmlElement(name = "web_application")
	public String getWebApplication() {
		return webApplication;
	}
	public void setWebApplication(String webApplication) {
		this.webApplication = webApplication;
	}
	
	public Date getCreated() {
		return created;
	}
	public void setCreated(Date created) {
		this.created = created;
	}
	public Date getExpired() {
		if (expired == null) {
			expired = new Date(created.getTime() + (getExpiresIn() * 1000));
		}
		return expired;
	}
	public void setExpired(Date expired) {
		this.expired = expired;
	}
	
	public void recreate() {
		this.created = new Date();
		this.expired = null;
	}
}
