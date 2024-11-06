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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.text.ParseException;

import be.nabu.libs.authentication.api.TokenSerializer;
import be.nabu.libs.types.TypeUtils;
import be.nabu.libs.types.api.ComplexType;
import be.nabu.libs.types.binding.api.Window;
import be.nabu.libs.types.binding.json.JSONBinding;
import be.nabu.libs.types.java.BeanInstance;
import be.nabu.libs.types.java.BeanResolver;

public class OAuth2TokenSerializer implements TokenSerializer<OAuth2Token> {

	@Override
	public void serialize(OutputStream output, OAuth2Token token) {
		JSONBinding binding = new JSONBinding((ComplexType) BeanResolver.getInstance().resolve(OAuth2SerializationToken.class), Charset.forName("UTF-8"));
		try {
			binding.marshal(output, new BeanInstance<OAuth2SerializationToken>(new OAuth2SerializationToken(token)));
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public OAuth2Token deserialize(InputStream input) {
		JSONBinding binding = new JSONBinding((ComplexType) BeanResolver.getInstance().resolve(OAuth2SerializationToken.class), Charset.forName("UTF-8"));
		try {
			OAuth2SerializationToken token = TypeUtils.getAsBean(binding.unmarshal(input, new Window[0]), OAuth2SerializationToken.class);
			return new OAuth2Token(token.getIdentity(), token.getRealm());
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
		catch (ParseException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public String getName() {
		return "oauth2";
	}

	@Override
	public Class<OAuth2Token> getTokenType() {
		return OAuth2Token.class;
	}

	public static class OAuth2SerializationToken {
		private OAuth2IdentityWithContext identity;
		private String realm;
		
		public OAuth2SerializationToken() {
			// auto
		}
		public OAuth2SerializationToken(OAuth2Token token) {
			this.realm = token.getRealm();
			this.identity = (OAuth2IdentityWithContext) token.getOAuth2Token();
		}
		
		public OAuth2IdentityWithContext getIdentity() {
			return identity;
		}
		public void setIdentity(OAuth2IdentityWithContext identity) {
			this.identity = identity;
		}
		public String getRealm() {
			return realm;
		}
		public void setRealm(String realm) {
			this.realm = realm;
		}
	}
}
