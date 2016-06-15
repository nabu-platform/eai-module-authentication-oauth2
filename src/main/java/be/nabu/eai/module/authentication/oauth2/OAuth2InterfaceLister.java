package be.nabu.eai.module.authentication.oauth2;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import be.nabu.eai.developer.api.InterfaceLister;
import be.nabu.eai.developer.util.InterfaceDescriptionImpl;

public class OAuth2InterfaceLister implements InterfaceLister {
	
	private static Collection<InterfaceDescription> descriptions = null;
	
	@Override
	public Collection<InterfaceDescription> getInterfaces() {
		if (descriptions == null) {
			synchronized(OAuth2InterfaceLister.class) {
				if (descriptions == null) {
					List<InterfaceDescription> descriptions = new ArrayList<InterfaceDescription>();
					descriptions.add(new InterfaceDescriptionImpl("Authentication", "OAuth2 Authenticator", "be.nabu.eai.module.authentication.oauth2.api.OAuth2Authenticator.authenticate"));
					OAuth2InterfaceLister.descriptions = descriptions;
				}
			}
		}
		return descriptions;
	}

}
