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
