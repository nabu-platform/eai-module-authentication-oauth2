package be.nabu.eai.module.authentication.oauth2;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import be.nabu.eai.repository.EAIRepositoryUtils;
import be.nabu.eai.repository.api.ArtifactRepositoryManager;
import be.nabu.eai.repository.api.Entry;
import be.nabu.eai.repository.api.ModifiableEntry;
import be.nabu.eai.repository.api.Repository;
import be.nabu.eai.repository.managers.base.JAXBArtifactManager;
import be.nabu.libs.resources.api.ResourceContainer;

public class OAuth2Manager extends JAXBArtifactManager<OAuth2Configuration, OAuth2Artifact> implements ArtifactRepositoryManager<OAuth2Artifact> {

	public OAuth2Manager() {
		super(OAuth2Artifact.class);
	}

	@Override
	protected OAuth2Artifact newInstance(String id, ResourceContainer<?> container, Repository repository) {
		return new OAuth2Artifact(id, container, repository);
	}

	@Override
	public List<Entry> addChildren(ModifiableEntry parent, OAuth2Artifact artifact) throws IOException {
		List<Entry> entries = new ArrayList<Entry>();
		if (artifact.getConfig().getClientId() == null) {
			entries.add(EAIRepositoryUtils.createChildEntry(parent, artifact, artifact.getConfigurationType()));
		}
		return entries;
	}

	@Override
	public List<Entry> removeChildren(ModifiableEntry parent, OAuth2Artifact artifact) throws IOException {
		List<Entry> entries = new ArrayList<Entry>();
		Entry structure = parent.getChild("oauth2Configuration");
		if (structure != null) {
			entries.add(structure);
			parent.removeChildren("oauth2Configuration");
		}
		return entries;
	}
	
}
