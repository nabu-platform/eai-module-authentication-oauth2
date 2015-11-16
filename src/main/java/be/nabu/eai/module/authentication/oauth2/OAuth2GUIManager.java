package be.nabu.eai.module.authentication.oauth2;

import java.io.IOException;
import java.util.List;

import be.nabu.eai.developer.MainController;
import be.nabu.eai.developer.managers.base.BaseJAXBGUIManager;
import be.nabu.eai.repository.resources.RepositoryEntry;
import be.nabu.libs.property.api.Property;
import be.nabu.libs.property.api.Value;

public class OAuth2GUIManager extends BaseJAXBGUIManager<OAuth2Configuration, OAuth2Artifact> {

	public OAuth2GUIManager() {
		super("OAuth2 Provider", OAuth2Artifact.class, new OAuth2Manager(), OAuth2Configuration.class);
	}

	@Override
	protected List<Property<?>> getCreateProperties() {
		return null;
	}

	@Override
	protected OAuth2Artifact newInstance(MainController controller, RepositoryEntry entry, Value<?>... values) throws IOException {
		return new OAuth2Artifact(entry.getId(), entry.getContainer(), entry.getRepository());
	}

	@Override
	public String getCategory() {
		return "Authentication";
	}
}
