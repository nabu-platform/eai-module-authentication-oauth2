package be.nabu.eai.module.authentication.oauth2;

import java.io.IOException;
import java.lang.reflect.Method;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import be.nabu.eai.module.authentication.oauth2.api.OAuth2Authenticator;
import be.nabu.eai.module.web.application.WebApplication;
import be.nabu.eai.module.web.application.WebFragment;
import be.nabu.eai.module.web.application.WebFragmentConfiguration;
import be.nabu.eai.module.web.application.WebFragmentPriority;
import be.nabu.eai.repository.EAIRepositoryUtils;
import be.nabu.eai.repository.api.Repository;
import be.nabu.eai.repository.artifacts.jaxb.JAXBArtifact;
import be.nabu.libs.authentication.api.Permission;
import be.nabu.libs.events.api.EventSubscription;
import be.nabu.libs.http.api.HTTPRequest;
import be.nabu.libs.http.api.HTTPResponse;
import be.nabu.libs.http.server.HTTPServerUtils;
import be.nabu.libs.resources.api.ResourceContainer;
import be.nabu.libs.types.SimpleTypeWrapperFactory;
import be.nabu.libs.types.api.ComplexContent;
import be.nabu.libs.types.api.ComplexType;
import be.nabu.libs.types.api.DefinedType;
import be.nabu.libs.types.api.Element;
import be.nabu.libs.types.base.SimpleElementImpl;
import be.nabu.libs.types.base.ValueImpl;
import be.nabu.libs.types.properties.MinOccursProperty;
import be.nabu.libs.types.structure.DefinedStructure;

public class OAuth2Artifact extends JAXBArtifact<OAuth2Configuration> implements WebFragment {

	private Map<String, EventSubscription<?, ?>> subscriptions = new HashMap<String, EventSubscription<?, ?>>();
	private DefinedStructure configuration;
	
	private String getKey(WebApplication artifact, String path) {
		return artifact.getId() + ":" + path;
	}
	
	public OAuth2Artifact(String id, ResourceContainer<?> directory, Repository repository) {
		super(id, directory, repository, "oauth2.xml", OAuth2Configuration.class);
	}
	
	public String getRelativePath() throws IOException {
		return getConfiguration().getServerPath() == null ? "/oauth/" + getId() : (getConfiguration().getServerPath().startsWith("/") ? "" : "/") + getConfiguration().getServerPath();
	}

	@Override
	public void stop(WebApplication application, String path) {
		String key = getKey(application, path);
		if (subscriptions.containsKey(key)) {
			synchronized(subscriptions) {
				if (subscriptions.containsKey(key)) {
					subscriptions.get(key).unsubscribe();
					subscriptions.remove(key);
				}
			}
		}
	}

	@Override
	public void start(WebApplication application, String path) throws IOException {
		ComplexContent configuration = application.getConfigurationFor(getConfig().getServerPath() == null ? "/" : getConfig().getServerPath(), getConfigurationType());
		Boolean enabled = configuration == null ? null : (Boolean) configuration.get("enabled");
		
		if (enabled == null || enabled) {
			String key = getKey(application, path);
			if (subscriptions.containsKey(key)) {
				stop(application, path);
			}
			String artifactPath = application.getConfiguration().getPath() == null || application.getConfiguration().getPath().isEmpty() ? "/" : application.getConfiguration().getPath();
			if (artifactPath.endsWith("/")) {
				artifactPath = artifactPath.substring(0, artifactPath.length() - 1);
			}
			if (getConfiguration().getServerPath() != null && !getConfiguration().getServerPath().isEmpty()) {
				artifactPath += (getConfiguration().getServerPath().startsWith("/") ? "" : "/") + getConfiguration().getServerPath();
			}
			if (application.getConfiguration().getVirtualHost() != null) {
				EventSubscription<HTTPRequest, HTTPResponse> subscription = application.getConfiguration().getVirtualHost().getDispatcher().subscribe(HTTPRequest.class, new OAuth2Listener(application, path, this));
				subscription.filter(HTTPServerUtils.limitToPath(artifactPath));
				subscriptions.put(key, subscription);
			}
		}
	}

	@Override
	public boolean isStarted(WebApplication application, String path) {
		return subscriptions.containsKey(getKey(application, path));
	}

	@Override
	public List<Permission> getPermissions(WebApplication artifact, String path) {
		return null;
	}
	
	@Override
	public WebFragmentPriority getPriority() {
		return WebFragmentPriority.HIGH;
	}

	@Override
	public List<WebFragmentConfiguration> getFragmentConfiguration() {
		List<WebFragmentConfiguration> configurations = new ArrayList<WebFragmentConfiguration>();
		if (getConfig().getAuthenticatorService() != null) {
			Method method = WebApplication.getMethod(OAuth2Authenticator.class, "authenticate");
			List<Element<?>> inputExtensions = EAIRepositoryUtils.getInputExtensions(getConfig().getAuthenticatorService(), method);
			for (final Element<?> extension : inputExtensions) {
				if (extension.getType() instanceof ComplexType && extension.getType() instanceof DefinedType) {
					configurations.add(new WebFragmentConfiguration() {
						@Override
						public ComplexType getType() {
							return (ComplexType) extension.getType();
						}
						@Override
						public String getPath() {
							return getConfig().getServerPath() == null ? "/" : getConfig().getServerPath();
						}
					});
				}
			}
		}
		// if client id is not filled in, generate a configuration for this oauth2 artifact
		if (getConfig().getClientId() == null) {
			configurations.add(new WebFragmentConfiguration() {
				@Override
				public ComplexType getType() {
					return getConfigurationType();
				}
				@Override
				public String getPath() {
					return getConfig().getServerPath() == null ? "/" : getConfig().getServerPath();
				}
			});
		}
		return configurations;
	}

	public DefinedStructure getConfigurationType() {
		if (configuration == null) {
			configuration = new DefinedStructure();
			configuration.setName("oauth2Configuration");
			configuration.setId(getId() + ".oauth2Configuration");
			configuration.add(new SimpleElementImpl<String>("clientId", SimpleTypeWrapperFactory.getInstance().getWrapper().wrap(String.class), configuration));
			configuration.add(new SimpleElementImpl<String>("clientSecret", SimpleTypeWrapperFactory.getInstance().getWrapper().wrap(String.class), configuration));
			configuration.add(new SimpleElementImpl<String>("name", SimpleTypeWrapperFactory.getInstance().getWrapper().wrap(String.class), configuration, new ValueImpl<Integer>(MinOccursProperty.getInstance(), 0)));
			if (getConfig().isMultipleEnvironments()) {
				configuration.add(new SimpleElementImpl<URI>("loginEndpoint", SimpleTypeWrapperFactory.getInstance().getWrapper().wrap(URI.class), configuration));
				configuration.add(new SimpleElementImpl<URI>("tokenEndpoint", SimpleTypeWrapperFactory.getInstance().getWrapper().wrap(URI.class), configuration));
				configuration.add(new SimpleElementImpl<URI>("apiEndpoint", SimpleTypeWrapperFactory.getInstance().getWrapper().wrap(URI.class), configuration));
				configuration.add(new SimpleElementImpl<URI>("redirectLink", SimpleTypeWrapperFactory.getInstance().getWrapper().wrap(URI.class), configuration));
			}
			configuration.add(new SimpleElementImpl<Boolean>("enabled", SimpleTypeWrapperFactory.getInstance().getWrapper().wrap(Boolean.class), configuration, new ValueImpl<Integer>(MinOccursProperty.getInstance(), 0)));
		}
		return configuration;
	}
}
