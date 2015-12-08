package be.nabu.eai.module.authentication.oauth2;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import be.nabu.libs.http.api.HTTPRequest;
import be.nabu.libs.http.api.HTTPResponse;
import be.nabu.libs.http.server.HTTPServerUtils;
import be.nabu.eai.repository.api.Repository;
import be.nabu.eai.repository.artifacts.jaxb.JAXBArtifact;
import be.nabu.libs.artifacts.api.StartableArtifact;
import be.nabu.libs.artifacts.api.StoppableArtifact;
import be.nabu.libs.events.api.EventSubscription;
import be.nabu.libs.resources.api.ResourceContainer;

public class OAuth2Artifact extends JAXBArtifact<OAuth2Configuration> implements StartableArtifact, StoppableArtifact {

	private boolean started;
	private List<EventSubscription<?, ?>> subscriptions = new ArrayList<EventSubscription<?, ?>>();
	
	public OAuth2Artifact(String id, ResourceContainer<?> directory, Repository repository) {
		super(id, directory, repository, "oauth2.xml", OAuth2Configuration.class);
	}
	
	public String getRelativePath() throws IOException {
		return getConfiguration().getServerPath() == null ? "/oauth/" + getId() : (getConfiguration().getServerPath().startsWith("/") ? "" : "/") + getConfiguration().getServerPath();
	}

	@Override
	public void stop() throws IOException {
		if (started) {
			// stop subscriptions
			for (EventSubscription<?, ?> subscription : subscriptions) {
				subscription.unsubscribe();
			}
			started = false;
		}
	}

	@Override
	public void start() throws IOException {
		String artifactPath = getConfiguration().getWebArtifact().getConfiguration().getPath() == null || getConfiguration().getWebArtifact().getConfiguration().getPath().isEmpty() ? "/" : getConfiguration().getWebArtifact().getConfiguration().getPath();
		if (artifactPath.endsWith("/")) {
			artifactPath = artifactPath.substring(0, artifactPath.length() - 1);
		}
		if (getConfiguration().getServerPath() != null && !getConfiguration().getServerPath().isEmpty()) {
			artifactPath += (getConfiguration().getServerPath().startsWith("/") ? "" : "/") + getConfiguration().getServerPath();
		}
		EventSubscription<HTTPRequest, HTTPResponse> subscription = getConfiguration().getWebArtifact().getDispatcher().subscribe(HTTPRequest.class, new OAuth2Listener(this));
		subscription.filter(HTTPServerUtils.limitToPath(artifactPath));
		subscriptions.add(subscription);
		started = true;
	}

	@Override
	public boolean isStarted() {
		return started;
	}
	
}
