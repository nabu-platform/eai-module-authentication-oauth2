package be.nabu.eai.module.authentication.oauth2;

import be.nabu.eai.repository.api.Repository;
import be.nabu.eai.repository.managers.base.JAXBArtifactManager;
import be.nabu.libs.resources.api.ResourceContainer;

public class OAuth2Manager extends JAXBArtifactManager<OAuth2Configuration, OAuth2Artifact> {

	public OAuth2Manager() {
		super(OAuth2Artifact.class);
	}

	@Override
	protected OAuth2Artifact newInstance(String id, ResourceContainer<?> container, Repository repository) {
		return new OAuth2Artifact(id, container, repository);
	}

}
