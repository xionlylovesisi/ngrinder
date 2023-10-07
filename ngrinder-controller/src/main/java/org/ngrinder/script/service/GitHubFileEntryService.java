package org.ngrinder.script.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.SerializationException;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.revwalk.RevCommit;
import org.eclipse.jgit.transport.UsernamePasswordCredentialsProvider;
import org.gitlab4j.api.GitLabApi;
import org.gitlab4j.api.GitLabApiException;
import org.gitlab4j.api.RepositoryApi;
import org.gitlab4j.api.models.Project;
import org.gitlab4j.api.models.TreeItem;
import org.kohsuke.github.*;
import org.ngrinder.common.exception.InvalidGitHubConfigurationException;
import org.ngrinder.common.exception.NGrinderRuntimeException;
import org.ngrinder.common.exception.PerfTestPrepareException;
import org.ngrinder.infra.config.Config;
import org.ngrinder.model.PerfTest;
import org.ngrinder.model.Status;
import org.ngrinder.model.User;
import org.ngrinder.perftest.service.PerfTestService;
import org.ngrinder.script.handler.GroovyGradleProjectScriptHandler;
import org.ngrinder.script.handler.GroovyMavenProjectScriptHandler;
import org.ngrinder.script.model.FileEntry;
import org.ngrinder.script.model.GitHubConfig;
import org.ngrinder.script.model.GitType;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.tmatesoft.svn.core.SVNException;
import org.tmatesoft.svn.core.SVNURL;
import org.tmatesoft.svn.core.auth.BasicAuthenticationManager;
import org.tmatesoft.svn.core.wc.SVNClientManager;
import org.tmatesoft.svn.core.wc.SVNStatus;
import org.tmatesoft.svn.core.wc.SVNStatusClient;
import org.tmatesoft.svn.core.wc.SVNUpdateClient;
import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.stream.Collectors.toList;
import static org.apache.commons.io.FileUtils.*;
import static org.apache.commons.io.FilenameUtils.getFullPath;
import static org.apache.commons.io.FilenameUtils.getName;
import static org.apache.commons.lang.StringUtils.isEmpty;
import static org.apache.commons.lang.StringUtils.isNotEmpty;
import static org.ngrinder.common.constant.CacheConstants.*;
import static org.ngrinder.common.constant.ControllerConstants.PROP_CONTROLLER_GITHUB_BASE_URL;
import static org.ngrinder.common.constant.ControllerConstants.PROP_CONTROLLER_GITLAB_BASE_URL;
import static org.ngrinder.common.util.AopUtils.proxy;
import static org.ngrinder.common.util.CollectionUtils.buildMap;
import static org.ngrinder.common.util.JsonUtils.deserialize;
import static org.ngrinder.common.util.NoOp.noOp;
import static org.ngrinder.common.util.PathUtils.removePrependedSlash;
import static org.ngrinder.common.util.TypeConvertUtils.cast;
import static org.ngrinder.script.model.FileType.getFileTypeByName;
import static org.ngrinder.script.model.GitHubConfig.CONFIG_NAME_MAX_LENGTH;
import static org.python.bouncycastle.crypto.tls.MACAlgorithm.sha;
import static org.tmatesoft.svn.core.SVNDepth.INFINITY;
import static org.tmatesoft.svn.core.SVNURL.parseURIEncoded;
import static org.tmatesoft.svn.core.wc.SVNClientManager.newInstance;
import static org.tmatesoft.svn.core.wc.SVNRevision.HEAD;
import static org.tmatesoft.svn.core.wc.SVNRevision.UNDEFINED;

/**
 * @since 3.5.0
 */
@Slf4j
@Service
public class GitHubFileEntryService {

	private static final String GITHUB_CONFIG_NAME = ".gitconfig.yml";

	private final FileEntryService fileEntryService;

	private final ObjectMapper objectMapper;

	private final Config config;

	private final PerfTestService perfTestService;

	private final GroovyMavenProjectScriptHandler groovyMavenProjectScriptHandler;

	private final GroovyGradleProjectScriptHandler groovyGradleProjectScriptHandler;

	private static final RateLimitHandlerEx rateLimitHandlerEx = new RateLimitHandlerEx();

	public GitHubFileEntryService(FileEntryService fileEntryService, ObjectMapper objectMapper,
								  Config config, @Lazy PerfTestService perfTestService,
								  GroovyMavenProjectScriptHandler groovyMavenProjectScriptHandler,
								  GroovyGradleProjectScriptHandler groovyGradleProjectScriptHandler) {
		this.fileEntryService = fileEntryService;
		this.objectMapper = objectMapper;
		this.config = config;
		this.perfTestService = perfTestService;
		this.groovyMavenProjectScriptHandler = groovyMavenProjectScriptHandler;
		this.groovyGradleProjectScriptHandler = groovyGradleProjectScriptHandler;
	}

	public FileEntry getGitHubOne(GHRepository ghRepository, GitHubConfig gitHubConfig, String scriptPath) {
		String fullPath = getGitHubCheckoutDirPath(ghRepository, gitHubConfig, scriptPath);
		String activeBranch = gitHubConfig.getBranch();
		if (isGitHubGroovyProjectScript(ghRepository, scriptPath, activeBranch)) {
			fullPath += groovyMavenProjectScriptHandler.getGroovyProjectPath(scriptPath);
			FileEntry fileEntry = createGitHubScriptFileEntry(fullPath);
			fileEntry.getProperties().put("type", proxy(this).getGitHubGroovyProjectType(ghRepository, scriptPath, activeBranch));
			fileEntry.getProperties().put("scriptPath", scriptPath);
			return fileEntry;
		} else {
			fullPath += getName(scriptPath);
			return createGitHubScriptFileEntry(fullPath);
		}
	}

	public FileEntry getGitLabOne(GitLabApi gitLabClient, GitHubConfig gitHubConfig, String scriptPath) {
		String fullPath = getGitLabCheckoutDirPath(gitLabClient, gitHubConfig, scriptPath);
		if (isGitLabGroovyProjectScript(gitLabClient, scriptPath, gitHubConfig)) {
			fullPath += groovyMavenProjectScriptHandler.getGroovyProjectPath(scriptPath);
			FileEntry fileEntry = createGitLabScriptFileEntry(fullPath);
			fileEntry.getProperties().put("type", proxy(this).getGitLabGroovyProjectType(gitLabClient, scriptPath, gitHubConfig));
			fileEntry.getProperties().put("scriptPath", scriptPath);
			return fileEntry;
		} else {
			fullPath += getName(scriptPath);
			return createGitHubScriptFileEntry(fullPath);
		}
	}

	public void checkoutGitHubScript(PerfTest perfTest, GHRepository ghRepository, GitHubConfig gitHubConfig) {
		String activeBranch;
		try {
			String defaultBranch = ghRepository.getDefaultBranch();
			String configuredBranch = gitHubConfig.getBranch();
			activeBranch = defaultBranch;

			if (!isEmpty(configuredBranch)) {
				activeBranch = configuredBranch;
			}
			gitHubConfig.setBranch(activeBranch);
			String sha = ghRepository.getBranch(activeBranch).getSHA1();
			String scriptPath = perfTest.getScriptName();
			String checkoutDirPath = getGitHubCheckoutDirPath(ghRepository, gitHubConfig, scriptPath);

			SVNClientManager svnClientManager = createSvnClientManager(gitHubConfig);

			SVNUpdateClient svnUpdateClient = svnClientManager.getUpdateClient();
			File checkoutDir = new File(checkoutDirPath);
			SVNURL checkoutUrl = createGitHubCheckoutUrl(ghRepository, scriptPath, gitHubConfig.getBranch(), defaultBranch);

			cleanUpGitHubStorage(svnClientManager.getStatusClient(), checkoutDir);

			perfTestService.markProgressAndStatus(perfTest, Status.CHECKOUT_SCRIPT, "Getting script from github.");
			if (!isSvnWorkingCopyDir(checkoutDir)) {
				if (checkoutDir.exists()) {
					deleteQuietly(checkoutDir);
				}
				svnUpdateClient.doCheckout(checkoutUrl, checkoutDir, HEAD, HEAD, INFINITY, true);
				saveSha(sha, checkoutDirPath);
				log.info("github checkout to: {}, url: {} sha: {}", checkoutDir, checkoutUrl.toString(), sha);
			} else {
				if (!isSameRevision(sha, checkoutDirPath)) {
					svnUpdateClient.doUpdate(checkoutDir, HEAD, INFINITY, true, true);
					saveSha(sha, checkoutDirPath);
					log.info("github update to: {}, sha: {}", checkoutDir, sha);
				}
			}
			perfTest.setScriptRevision(createScriptRevisionUrl(ghRepository.getSvnUrl(), sha, scriptPath));
		} catch (Exception e) {
			throw new PerfTestPrepareException("Failed to checkout scripts from github.\n" +
				"Please check your github configuration.\n\n" + e.getMessage(), e);
		}
	}

	public void checkoutGitLabScript(PerfTest perfTest, GitLabApi gitlabClient, GitHubConfig gitConfig) {
		String activeBranch;
		Git git = null;
		try {
			Project project = gitlabClient.getProjectApi().getProject(gitConfig.getOwner(), gitConfig.getRepo());
			String defaultBranch = project.getDefaultBranch();
			String configuredBranch = gitConfig.getBranch();
			activeBranch = defaultBranch;

			if (!isEmpty(configuredBranch)) {
				activeBranch = configuredBranch;
			}
			gitConfig.setBranch(activeBranch);
			String scriptPath = perfTest.getScriptName();
			String checkoutDirPath = getGitLabCheckoutDirPath(gitlabClient, gitConfig, scriptPath);
			File checkoutDir = new File(checkoutDirPath);

			perfTestService.markProgressAndStatus(perfTest, Status.CHECKOUT_SCRIPT, "Getting script from github.");
			boolean alreadyExists = checkoutDir.exists() && checkoutDir.isDirectory();
			UsernamePasswordCredentialsProvider oauth2 = new UsernamePasswordCredentialsProvider("oauth2", gitConfig.getAccessToken());
			if (alreadyExists) {
				git = Git.open(checkoutDir);
				for (RevCommit revCommit : git.log().call()) {
					String localSha = revCommit.getName();
					String latestSha = gitlabClient.getCommitsApi().getCommits(project.getId(), activeBranch, null, null, 1).current().get(0).getId();
					if (!localSha.equals(latestSha)) {
						git.pull().setCredentialsProvider(oauth2).call();
						saveSha(latestSha, checkoutDirPath);
						log.info("gitlab update to: {}, sha: {}", checkoutDir, latestSha);
					}
					break;
				}
			} else {
				// clone and checkout branch
				git = Git.cloneRepository()
					.setURI(project.getHttpUrlToRepo())
					.setBranch(activeBranch)
					.setCredentialsProvider(oauth2)
					.setDirectory(checkoutDir).call();
				String sha = null;
				for (RevCommit revCommit : git.log().call()) {
					sha = revCommit.getName();
					break;
				}
				saveSha(sha, checkoutDirPath);
				log.info("gitlab checkout to: {}, url: {} sha: {}", checkoutDir, project.getHttpUrlToRepo(), sha);
			}
			perfTest.setScriptRevision(createGitLabScriptRevisionUrl(gitConfig, scriptPath));
		} catch (Exception e) {
			throw new PerfTestPrepareException("Failed to checkout scripts from gitlab.\n" +
				"Please check your gitlab configuration.\n\n" + e.getMessage(), e);
		} finally {
			if (git != null) {
				git.close();
			}
		}
	}

	private void cleanUpGitHubStorage(SVNStatusClient svnStatusClient, File checkoutDir) {
		try {
			SVNStatus svnStatus = svnStatusClient.doStatus(checkoutDir, true);
			if (!svnStatus.getRemoteRevision().equals(UNDEFINED)) {
				String repositoryRootPath = svnStatus.getRepositoryRootURL().getPath();
				deleteQuietly(new File(checkoutDir.getAbsolutePath().split(repositoryRootPath)[0] + repositoryRootPath));
			}
		} catch (SVNException | NullPointerException e) {
			noOp();
		}
	}

	private String createScriptRevisionUrl(String baseUrl, String treeSha, String scriptPath) {
		return baseUrl + "/blob/" + treeSha + "/" + scriptPath;
	}

	private String createGitLabScriptRevisionUrl(GitHubConfig gitHubConfig, String scriptPath) {
		return getGitlabBaseUrl(gitHubConfig) + "/" + gitHubConfig.getOwner() + "/" + gitHubConfig.getRepo() + "/-/blob/" + gitHubConfig.getBranch() + "/" + scriptPath;
	}

	private SVNClientManager createSvnClientManager(GitHubConfig gitHubConfig) {
		// userName is don't care parameter if using access token.
		BasicAuthenticationManager basicAuthenticationManager
			= new BasicAuthenticationManager("ngrinder", gitHubConfig.getAccessToken());

		SVNClientManager svnClientManager = newInstance();
		svnClientManager.setAuthenticationManager(basicAuthenticationManager);
		return svnClientManager;
	}

	private boolean isDefaultBranch(String configuredBranch, String defaultBranch) {
		return isEmpty(configuredBranch) || configuredBranch.equals(defaultBranch);
	}

	private boolean isSvnWorkingCopyDir(File directory) {
		if (!directory.exists() || !directory.isDirectory()) {
			return false;
		}
		return new File(directory.getPath() + "/.svn").exists();
	}

	public boolean isGitHubGroovyProjectScript(GHRepository ghRepository, String scriptPath, String activeBranch) {
		if (!groovyMavenProjectScriptHandler.isGroovyProjectScriptPath(scriptPath)) {
			return false;
		}
		return proxy(this).getGitHubGroovyProjectType(ghRepository, scriptPath, activeBranch) != null;
	}

	@Cacheable(value = LOCAL_CACHE_GITHUB_GROOVY_PROJECT_SCRIPT_TYPE, key = "#ghRepository.svnUrl + #scriptPath + #activeBranch")
	public String getGitHubGroovyProjectType(GHRepository ghRepository, String scriptPath, String activeBranch) {
		try {
			List<GHContent> ghContents = ghRepository.getDirectoryContent(groovyMavenProjectScriptHandler.getBasePath(scriptPath), activeBranch);
			for (GHContent ghContent : ghContents) {
				String fileName = ghContent.getName();
				if (StringUtils.equals(fileName, groovyMavenProjectScriptHandler.getBuildScriptName())) {
					return groovyMavenProjectScriptHandler.getKey();
				}

				if (StringUtils.equals(fileName, groovyGradleProjectScriptHandler.getBuildScriptName())) {
					return groovyGradleProjectScriptHandler.getKey();
				}
			}
		} catch (IOException ignored) {
			noOp();
		}
		return null;
	}

	public boolean isGitLabGroovyProjectScript(GitLabApi gitLabApi, String scriptPath, GitHubConfig gitHubConfig) {
		if (!groovyMavenProjectScriptHandler.isGroovyProjectScriptPath(scriptPath)) {
			return false;
		}
		return proxy(this).getGitLabGroovyProjectType(gitLabApi, scriptPath, gitHubConfig) != null;
	}

	@Cacheable(value = LOCAL_CACHE_GITLAB_GROOVY_PROJECT_SCRIPT_TYPE, key = "#gitLabApi.gitLabServerUrl + #scriptPath + #gitHubConfig.branch")
	public String getGitLabGroovyProjectType(GitLabApi gitLabApi, String scriptPath, GitHubConfig gitHubConfig) {
		try {
			String basePath = groovyMavenProjectScriptHandler.getBasePath(scriptPath);
			List<TreeItem> tree = gitLabApi.getRepositoryApi().getTree(gitHubConfig.getOwner() + "/" + gitHubConfig.getRepo(), basePath, gitHubConfig.getBranch());
			for (TreeItem treeItem : tree) {
				String fileName = treeItem.getName();
				if (StringUtils.equals(fileName, groovyMavenProjectScriptHandler.getBuildScriptName())) {
					return groovyMavenProjectScriptHandler.getKey();
				}

				if (StringUtils.equals(fileName, groovyGradleProjectScriptHandler.getBuildScriptName())) {
					return groovyGradleProjectScriptHandler.getKey();
				}
			}
		} catch (GitLabApiException ignored) {
			noOp();
		}
		return null;
	}


	private FileEntry createGitHubScriptFileEntry(String fullPath) {
		FileEntry fileEntry = new FileEntry();
		fileEntry.setFileType(getFileTypeByName(fullPath));
		fileEntry.setPath(fullPath);
		fileEntry.setRevision(-1L);
		fileEntry.setProperties(buildMap("scm", GitType.GITHUB.getValue()));
		return fileEntry;
	}

	private FileEntry createGitLabScriptFileEntry(String fullPath) {
		FileEntry fileEntry = new FileEntry();
		fileEntry.setFileType(getFileTypeByName(fullPath));
		fileEntry.setPath(fullPath);
		fileEntry.setRevision(-1L);
		fileEntry.setProperties(buildMap("scm", GitType.GITLAB.getValue()));
		return fileEntry;
	}

	private void saveSha(String sha, String checkoutDirPath) throws IOException {
		writeStringToFile(getShaFile(checkoutDirPath), sha, UTF_8);
	}

	private boolean isSameRevision(String sha, String checkoutDirPath) throws IOException {
		File shaFile = getShaFile(checkoutDirPath);
		if (!shaFile.exists()) {
			return false;
		}

		String oldSha = readFileToString(shaFile, UTF_8).trim();
		return StringUtils.equals(sha, oldSha);
	}

	private File getShaFile(String checkoutDirPath) {
		return new File(checkoutDirPath + "/.sha");
	}

	private String getGitHubCheckoutDirPath(GHRepository ghRepository, GitHubConfig gitHubConfig, String scriptPath) {
		try {
			String checkoutScriptPath;
			URI uri = new URI(getGitHubBaseUrl(gitHubConfig));
			if (isGitHubGroovyProjectScript(ghRepository, scriptPath, gitHubConfig.getBranch())) {
				checkoutScriptPath = groovyMavenProjectScriptHandler.getBasePath(scriptPath);
			} else {
				checkoutScriptPath = getFullPath(scriptPath);
			}
			return config.getHome().getDirectory().getPath() + "/github/" + uri.getHost()
				+ "/" + gitHubConfig.getOwner() + "/" + gitHubConfig.getRepo() + "/" + checkoutScriptPath;
		} catch (URISyntaxException e) {
			throw new NGrinderRuntimeException(e);
		}
	}

	private String getGitLabCheckoutDirPath(GitLabApi gitLabApi, GitHubConfig gitHubConfig, String scriptPath) {
		try {
			String checkoutScriptPath;
			URI uri = new URI(getGitlabBaseUrl(gitHubConfig));

			if (isGitLabGroovyProjectScript(gitLabApi, scriptPath, gitHubConfig)) {
				checkoutScriptPath = groovyMavenProjectScriptHandler.getBasePath(scriptPath);
			} else {
				checkoutScriptPath = getFullPath(scriptPath);
			}
			return config.getHome().getDirectory().getPath() + "/github/" + uri.getHost()
				+ "/" + gitHubConfig.getOwner() + "/" + gitHubConfig.getRepo() + "/" + checkoutScriptPath;
		} catch (URISyntaxException e) {
			throw new NGrinderRuntimeException(e);
		}
	}

	/**
	 * get all github configuration of {@link User}.
	 *
	 * @param user user.
	 * @return list of github configuration.
	 * @since 3.5.0
	 */
	public Set<GitHubConfig> getAllGitHubConfig(User user) throws FileNotFoundException {
		FileEntry gitConfigYaml = fileEntryService.getOne(user, GITHUB_CONFIG_NAME, -1L);
		if (gitConfigYaml == null) {
			throw new FileNotFoundException(GITHUB_CONFIG_NAME + " isn't exist.");
		}

		return getAllGithubConfig(gitConfigYaml);
	}

	private Set<GitHubConfig> getAllGithubConfig(FileEntry gitConfigYaml) {
		Set<GitHubConfig> gitHubConfig = new HashSet<>();
		// Yaml is not thread safe. so create it every time.
		Yaml yaml = new Yaml();
		Iterable<Map<String, Object>> gitConfigs = cast(yaml.loadAll(gitConfigYaml.getContent()));
		for (Map<String, Object> configMap : gitConfigs) {
			if (configMap == null) {
				continue;
			}
			configMap.put("revision", gitConfigYaml.getRevision());
			GitHubConfig config = objectMapper.convertValue(configMap, GitHubConfig.class);

			if (gitHubConfig.contains(config)) {
				throw new InvalidGitHubConfigurationException("GitHub configuration '"
					+ config.getName() + "' is duplicated.\nPlease check your .gitconfig.yml");
			}

			gitHubConfig.add(config);
		}
		return gitHubConfig;
	}

	/**
	 * get github configuration by name.
	 *
	 * @param user user.
	 * @param name configuration name.
	 * @return list of github configuration.
	 * @since 3.5.0
	 */
	public GitHubConfig getGitHubConfig(User user, String name) throws FileNotFoundException {
		Set<GitHubConfig> gitHubConfigs = getAllGitHubConfig(user);
		Optional<GitHubConfig> gitHubConfigOptional = gitHubConfigs.stream()
			.filter(config -> StringUtils.equals(config.getName(), name))
			.findFirst();

		if (!gitHubConfigOptional.isPresent()) {
			throw new InvalidGitHubConfigurationException("GitHub configuration(" + name + ") is not exist");
		}
		return gitHubConfigOptional.get();
	}

	public boolean validate(FileEntry gitConfigYaml) {
		for (GitHubConfig config : getAllGithubConfig(gitConfigYaml)) {
			try {
				String configName = config.getName();
				if (configName.length() > CONFIG_NAME_MAX_LENGTH) {
					throw new NGrinderRuntimeException(
						"Invalid github configuration.(" + config.getName() + ")\n" +
							"Configuration name must be shorter than " + CONFIG_NAME_MAX_LENGTH
					);
				}
				if (config.isGitHub()) {
					validateGitHubConfig(config);
				} else if (config.isGitLab()) {
					validateGitLabConfig(config);
				}
			} catch (Exception e) {
				Map<String, String> errorJson = parseGitHubConfigurationErrorMessage(e.getMessage());
				throw new InvalidGitHubConfigurationException("Invalid github configuration.(" + config.getName() + ")\n" + errorJson.get("message"));
			}
		}
		return true;
	}

	private void validateGitLabConfig(GitHubConfig config) throws GitLabApiException {
		Project project = getGitLabClient(config).getProjectApi().getProject(config.getOwner(), config.getRepo());
		RepositoryApi repositoryApi = getGitLabClient(config).getRepositoryApi();
		if (isNotEmpty(config.getBranch())) {
			repositoryApi.getBranch(project.getId(), config.getBranch());
		} else {
			repositoryApi.getBranches(project.getId(), project.getDefaultBranch());
		}
	}

	private void validateGitHubConfig(GitHubConfig config) throws IOException {
		GHRepository ghRepository = getGitHubClient(config).getRepository(config.getOwner() + "/" + config.getRepo());
		String branch = config.getBranch();
		if (isNotEmpty(branch)) {
			ghRepository.getBranch(branch);
		}
	}

	private Map<String, String> parseGitHubConfigurationErrorMessage(String errorMessage) {
		try {
			Map<String, String> errorJson = deserialize(errorMessage, new TypeReference<Map<String, String>>() {
			});
			errorJson.putIfAbsent("message", errorMessage);
			return errorJson;
		} catch (SerializationException e) {
			return buildMap("message", errorMessage);
		}
	}

	/**
	 * Get ngrinder test scripts from user github repository.
	 *
	 * @since 3.5.0
	 */
	@Cacheable(value = LOCAL_CACHE_GITHUB_SCRIPTS, key = "#user.userId")
	public Map<String, List<GHTreeEntry>> getScripts(User user) throws FileNotFoundException {
		Map<String, List<GHTreeEntry>> scriptMap = new HashMap<>();
		getAllGitHubConfig(user).forEach(gitHubConfig -> {
			try {
				List<GHTreeEntry> scripts = null;
				if (gitHubConfig.isGitHub()) {
					scripts = getGitHubScripts(gitHubConfig);
				} else if (gitHubConfig.isGitLab()) {
					scripts = getGitLabScripts(gitHubConfig);
				}
				if (Objects.nonNull(scripts)) {
					scriptMap.put(gitHubConfig.getName() + ":" + gitHubConfig.getRevision(), scripts);
				}

			} catch (IOException e) {
				log.error("Fail to get script from github with [userId({}), {}]", user.getUserId(), gitHubConfig, e);
				throw new NGrinderRuntimeException("Fail to get script from github.\ncause: " + e.getCause(), e);
			}
		});
		return scriptMap;
	}

	private List<GHTreeEntry> getGitLabScripts(GitHubConfig gitHubConfig) {
		GitLabApi gitLabClient = getGitLabClient(gitHubConfig);
		try {
			Project project = gitLabClient.getProjectApi().getProject(gitHubConfig.getOwner(), gitHubConfig.getRepo());
			String activeBranch = project.getDefaultBranch();
			if (isNotEmpty(gitHubConfig.getBranch())) {
				activeBranch = gitHubConfig.getBranch();
			}
			List<org.gitlab4j.api.models.TreeItem> treeItems = gitLabClient.getRepositoryApi().getTree(project.getId(), gitHubConfig.getScriptRoot(), activeBranch, true);
			List<GHTreeEntry> allFiles = treeItems.stream().map(treeItem -> GHTreeEntry.fromGitLabTreeItem(treeItem, gitHubConfig)).collect(toList());
			List<GHTreeEntry> scripts = filterScript(allFiles, removePrependedSlash(gitHubConfig.getScriptRoot()));
			return scripts;
		} catch (GitLabApiException e) {
			log.error("Fail to get script from gitlab with [{}]", gitHubConfig, e);
			throw new NGrinderRuntimeException("Fail to get script from gitlab.\ncause: " + e.getCause(), e);
		}
	}

	private List<GHTreeEntry> getGitHubScripts(GitHubConfig gitHubConfig) throws IOException {
		GitHub gitHub = getGitHubClient(gitHubConfig);
		GHRepository ghRepository = gitHub.getRepository(gitHubConfig.getOwner() + "/" + gitHubConfig.getRepo());

		String defaultBranch = ghRepository.getDefaultBranch();
		String configuredBranch = gitHubConfig.getBranch();
		String activeBranch = defaultBranch;

		if (!isEmpty(configuredBranch)) {
			activeBranch = configuredBranch;
		}
		String shaOfDefaultBranch = ghRepository.getBranch(activeBranch).getSHA1();
		List<GHTreeEntry> allFiles = ghRepository.getTreeRecursive(shaOfDefaultBranch, 1).getTree();
		List<GHTreeEntry> scripts = filterScript(allFiles, removePrependedSlash(gitHubConfig.getScriptRoot()));

		if (scripts.size() > 0) {
			scripts.forEach(script -> script.setSha(createScriptRevisionUrl(ghRepository.getSvnUrl(), shaOfDefaultBranch, script.getPath())));
		}
		return scripts;
	}

	private SVNURL createGitHubCheckoutUrl(GHRepository ghRepository,
										   String scriptPath,
										   String activeBranch,
										   String defaultBranch) throws SVNException {
		boolean isDefaultBranch = isDefaultBranch(activeBranch, defaultBranch);
		String checkoutBaseUrl = ghRepository.getSvnUrl();
		checkoutBaseUrl += isDefaultBranch ? "/trunk" : "/branches/" + activeBranch;
		SVNURL checkoutUrl;
		if (isGitHubGroovyProjectScript(ghRepository, scriptPath, activeBranch)) {
			checkoutUrl = parseURIEncoded(checkoutBaseUrl + "/" + groovyMavenProjectScriptHandler.getBasePath(scriptPath));
		} else {
			checkoutUrl = parseURIEncoded(checkoutBaseUrl + "/" + getFullPath(scriptPath));
		}
		return checkoutUrl;
	}

	private SVNURL createGitLabCheckoutUrl(GitLabApi gitLabApi,
										   String scriptPath,
										   GitHubConfig gitHubConfig) throws SVNException {
		String checkoutBaseUrl = getGitlabBaseUrl(gitHubConfig) + "/" + gitHubConfig.getOwner() + "/" + gitHubConfig.getRepo() + "/-/tree/" + gitHubConfig.getBranch();
		SVNURL checkoutUrl;
		if (isGitLabGroovyProjectScript(gitLabApi, scriptPath, gitHubConfig)) {
			checkoutUrl = parseURIEncoded(checkoutBaseUrl + "/" + groovyMavenProjectScriptHandler.getBasePath(scriptPath));
		} else {
			checkoutUrl = parseURIEncoded(checkoutBaseUrl + "/" + getFullPath(scriptPath));
		}
		return checkoutUrl;
	}

	/**
	 * Create GitHub client from {@link GitHubConfig}.
	 *
	 * @since 3.5.0
	 */
	public GitHub getGitHubClient(GitHubConfig gitHubConfig) {
		String baseUrl = getGitHubBaseUrl(gitHubConfig);
		String accessToken = gitHubConfig.getAccessToken();

		GitHubBuilder gitHubBuilder = new GitHubBuilder().withRateLimitHandler(rateLimitHandlerEx);

		if (isNotEmpty(baseUrl)) {
			gitHubBuilder.withEndpoint(baseUrl);
		}

		if (isNotEmpty(accessToken)) {
			gitHubBuilder.withOAuthToken(accessToken);
		}

		try {
			return gitHubBuilder.build();
		} catch (IOException e) {
			log.error("Fail to creation of github client from {}", gitHubConfig, e);
			Map<String, String> errorJson = parseGitHubConfigurationErrorMessage(e.getMessage());
			throw new InvalidGitHubConfigurationException("Fail to creation of github client.\n" + errorJson.get("message"));
		}
	}

	public GitLabApi getGitLabClient(GitHubConfig gitHubConfig) {
		String baseUrl = getGitlabBaseUrl(gitHubConfig);
		String accessToken = gitHubConfig.getAccessToken();
		return new GitLabApi(baseUrl, accessToken);
	}

	private List<GHTreeEntry> filterScript(List<GHTreeEntry> ghTreeEntries, String scriptRoot) {
		return ghTreeEntries
			.stream()
			.filter(ghTreeEntry -> isScript(ghTreeEntry, scriptRoot))
			.collect(toList());
	}

	private boolean isScript(GHTreeEntry ghTreeEntry, String scriptRoot) {
		String path = ghTreeEntry.getPath();
		return ghTreeEntry.getType().endsWith("blob") && path.contains(scriptRoot)
			&& (path.endsWith(".groovy") || path.endsWith(".py"));
	}

	private String getGitHubBaseUrl(GitHubConfig gitHubConfig) {
		String configuredGitHubBaseUrl = gitHubConfig.getBaseUrl();
		return (!configuredGitHubBaseUrl.isEmpty()) ? configuredGitHubBaseUrl : config.getControllerProperties().getProperty(PROP_CONTROLLER_GITHUB_BASE_URL);
	}

	private String getGitlabBaseUrl(GitHubConfig gitHubConfig) {
		String configuredGitHubBaseUrl = gitHubConfig.getBaseUrl();
		return (!configuredGitHubBaseUrl.isEmpty()) ? configuredGitHubBaseUrl : config.getControllerProperties().getProperty(PROP_CONTROLLER_GITLAB_BASE_URL);
	}

	@CacheEvict(value = LOCAL_CACHE_GITHUB_SCRIPTS, key = "#user.userId")
	public void evictGitHubScriptCache(User user) {
		noOp();
	}

	@CacheEvict(value = LOCAL_CACHE_GITHUB_GROOVY_PROJECT_SCRIPT_TYPE, key = "#ghRepository.svnUrl + #scriptPath + #activeBranch")
	public void evictGitHubGroovyProjectScriptTypeCache(GHRepository ghRepository, String scriptPath, String activeBranch) {
		noOp();
	}

	public FileEntry prepareDistribution(User user, String gitConfigName, PerfTest perfTest) throws IOException {
		GitHubConfig gitHubConfig = this.getGitHubConfig(user, gitConfigName);
		String scriptName = perfTest.getScriptName();
		FileEntry scriptEntry;
		if (gitHubConfig.isGitHub()) {
			GitHub gitHub = this.getGitHubClient(gitHubConfig);
			GHRepository ghRepository = gitHub.getRepository(gitHubConfig.getOwner() + "/" + gitHubConfig.getRepo());
			this.checkoutGitHubScript(perfTest, ghRepository, gitHubConfig);
			scriptEntry = this.getGitHubOne(ghRepository, gitHubConfig, scriptName);
			this.evictGitHubGroovyProjectScriptTypeCache(ghRepository, scriptName, gitHubConfig.getBranch());
		} else {
			GitLabApi gitLabClient = this.getGitLabClient(gitHubConfig);
			this.checkoutGitLabScript(perfTest, gitLabClient, gitHubConfig);
			scriptEntry = this.getGitLabOne(gitLabClient, gitHubConfig, scriptName);
		}
		return scriptEntry;
	}

	public static class RateLimitHandlerEx extends RateLimitHandler {
		@Override
		public void onError(IOException e, HttpURLConnection uc) {
			throw new NGrinderRuntimeException("GitHub api rate limit was hit.", e);
		}
	}
}
