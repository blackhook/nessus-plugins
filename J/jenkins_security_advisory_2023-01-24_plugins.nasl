#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171929);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/28");

  script_cve_id(
    "CVE-2023-24422",
    "CVE-2023-24423",
    "CVE-2023-24424",
    "CVE-2023-24425",
    "CVE-2023-24426",
    "CVE-2023-24427",
    "CVE-2023-24428",
    "CVE-2023-24429",
    "CVE-2023-24430",
    "CVE-2023-24431",
    "CVE-2023-24432",
    "CVE-2023-24433",
    "CVE-2023-24434",
    "CVE-2023-24435",
    "CVE-2023-24436",
    "CVE-2023-24437",
    "CVE-2023-24438",
    "CVE-2023-24439",
    "CVE-2023-24440",
    "CVE-2023-24441",
    "CVE-2023-24442",
    "CVE-2023-24443",
    "CVE-2023-24444",
    "CVE-2023-24445",
    "CVE-2023-24446",
    "CVE-2023-24447",
    "CVE-2023-24448",
    "CVE-2023-24449",
    "CVE-2023-24450",
    "CVE-2023-24451",
    "CVE-2023-24452",
    "CVE-2023-24453",
    "CVE-2023-24454",
    "CVE-2023-24455",
    "CVE-2023-24456",
    "CVE-2023-24457",
    "CVE-2023-24458",
    "CVE-2023-24459"
  );

  script_name(english:"Jenkins plugins Multiple Vulnerabilities (2023-01-24)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to their self-reported version numbers, the version of Jenkins plugins running on the remote web server are
affected by multiple vulnerabilities:

  - High Script Security Plugin provides a sandbox feature that allows low privileged users to define scripts,
    including Pipelines, that are generally safe to execute. Calls to code defined inside a sandboxed script
    are intercepted, and various allowlists are checked to determine whether the call is to be allowed. In
    Script Security Plugin 1228.vd93135a_2fb_25 and earlier, property assignments performed implicitly by the
    Groovy language runtime when invoking map constructors were not intercepted by the sandbox. This
    vulnerability allows attackers with permission to define and run sandboxed scripts, including Pipelines,
    to bypass the sandbox protection and execute arbitrary code in the context of the Jenkins controller JVM.
    Script Security Plugin 1229.v4880b_b_e905a_6 intercepts property assignments when invoking map
    constructors. As part of this fix, map constructors may only be invoked in the sandbox using the new key.
    Attempting to invoke a map constructor using a Groovy cast will fail unconditionally. For example, code
    such as [key: value] as MyClass or MyClass mc = [key: value] must be converted to use new MyClass(key:
    value) instead. (CVE-2023-24422)

  - Medium Gerrit Trigger Plugin 2.38.0 and earlier does not require POST requests for several HTTP endpoints,
    resulting in a cross-site request forgery (CSRF) vulnerability. This vulnerability allows attackers to
    rebuild previous builds triggered by Gerrit. Gerrit Trigger Plugin 2.38.1 requires POST requests for the
    affected HTTP endpoints. (CVE-2023-24423)

  - High OpenId Connect Authentication Plugin 2.4 and earlier does not invalidate the existing session on
    login. This allows attackers to use social engineering techniques to gain administrator access to Jenkins.
    OpenId Connect Authentication Plugin 2.5 invalidates the existing session on login. (CVE-2023-24424)

  - Medium Kubernetes Credentials Provider Plugin 1.208.v128ee9800c04 and earlier does not set the appropriate
    context for Kubernetes credentials lookup, allowing the use of System-scoped credentials otherwise
    reserved for the global configuration. This allows attackers with Item/Configure permission to access and
    potentially capture Kubernetes credentials they are not entitled to. Kubernetes Credentials Provider
    Plugin 1.209.v862c6e5fb_1ef defines the appropriate context for Kubernetes credentials lookup.
    (CVE-2023-24425)

  - High Azure AD Plugin 303.va_91ef20ee49f and earlier does not invalidate the existing session on login.
    This allows attackers to use social engineering techniques to gain administrator access to Jenkins. Azure
    AD Plugin 306.va_7083923fd50 invalidates the existing session on login. (CVE-2023-24426)

  - High Bitbucket OAuth Plugin 0.12 and earlier does not invalidate the existing session on login. This
    allows attackers to use social engineering techniques to gain administrator access to Jenkins. Bitbucket
    OAuth Plugin 0.13 invalidates the existing session on login. (CVE-2023-24427)

  - Medium Bitbucket OAuth Plugin 0.12 and earlier does not implement a state parameter in its OAuth flow, a
    unique and non-guessable value associated with each authentication request. This vulnerability allows
    attackers to trick users into logging in to the attacker's account. Bitbucket OAuth Plugin 0.13 implements
    a state parameter in its OAuth flow. (CVE-2023-24428)

  - High Semantic Versioning Plugin defines a controller/agent message that processes a given file as XML and
    its XML parser is not configured to prevent XML external entity (XXE) attacks. Semantic Versioning Plugin
    1.14 and earlier does not restrict execution of the controller/agent message to agents, and implements no
    limitations about the file path that can be parsed. This allows attackers able to control agent processes
    to have Jenkins parse a crafted file that uses external entities for extraction of secrets from the
    Jenkins controller or server-side request forgery. This is due to an incomplete fix of SECURITY-2124. This
    vulnerability is only exploitable in Jenkins 2.318 and earlier, LTS 2.303.2 and earlier. See the LTS
    upgrade guide. Semantic Versioning Plugin 1.15 does not allow the affected controller/agent message to be
    submitted by agents for execution on the controller. (CVE-2023-24429)

  - Medium Semantic Versioning Plugin 1.14 and earlier does not configure its XML parser to prevent XML
    external entity (XXE) attacks. This allows attackers able to control the contents of the version file for
    the 'Determine Semantic Version' build step to have agent processes parse a crafted file that uses
    external entities for extraction of secrets from the Jenkins agent or server-side request forgery. Because
    Jenkins agent processes usually execute build tools whose input (source code, build scripts, etc.) is
    controlled externally, this vulnerability only has a real impact in very narrow circumstances: when
    attackers can control XML files, but are unable to change build steps, Jenkinsfiles, test code that gets
    executed on the agents, or similar. Semantic Versioning Plugin 1.15 disables external entity resolution
    for its XML parser. (CVE-2023-24430)

  - Medium Orka by MacStadium Plugin 1.31 and earlier does not perform permission checks in several HTTP
    endpoints. This allows attackers with Overall/Read permission to enumerate credentials IDs of credentials
    stored in Jenkins. Those can be used as part of an attack to capture the credentials using another
    vulnerability. An enumeration of credentials IDs in Orka by MacStadium Plugin 1.32 requires
    Overall/Administer permission. (CVE-2023-24431)

  - Medium Orka by MacStadium Plugin 1.31 and earlier does not perform permission checks in several HTTP
    endpoints. This allows attackers with Overall/Read permission to connect to an attacker-specified HTTP
    server using attacker-specified credentials IDs obtained through another method, capturing credentials
    stored in Jenkins. Additionally, these HTTP endpoints do not require POST requests, resulting in a cross-
    site request forgery (CSRF) vulnerability. Orka by MacStadium Plugin 1.32 requires POST requests and
    Overall/Administer permission for the affected HTTP endpoints. (CVE-2023-24432, CVE-2023-24433)

  - Medium GitHub Pull Request Builder Plugin 1.42.2 and earlier does not perform a permission check in an
    HTTP endpoint. This allows attackers with Overall/Read permission to enumerate credentials IDs of
    credentials stored in Jenkins. Those can be used as part of an attack to capture the credentials using
    another vulnerability. As of publication of this advisory, there is no fix. Learn why we announce this.
    (CVE-2023-24436)

  - Medium GitHub Pull Request Builder Plugin 1.42.2 and earlier does not perform permission checks in methods
    implementing form validation. This allows attackers with Overall/Read permission to connect to an
    attacker-specified URL using attacker-specified credentials IDs obtained through another method, capturing
    credentials stored in Jenkins. Additionally, these form validation methods do not require POST requests,
    resulting in a cross-site request forgery (CSRF) vulnerability. As of publication of this advisory, there
    is no fix. Learn why we announce this. (CVE-2023-24434, CVE-2023-24435)

  - Medium JIRA Pipeline Steps Plugin 2.0.165.v8846cf59f3db and earlier does not perform permission checks in
    methods implementing form validation. This allows attackers with Overall/Read permission to connect to an
    attacker-specified URL using attacker-specified credentials IDs obtained through another method, capturing
    credentials stored in Jenkins. Additionally, these form validation methods do not require POST requests,
    resulting in a cross-site request forgery (CSRF) vulnerability. As of publication of this advisory, there
    is no fix. Learn why we announce this. (CVE-2023-24437, CVE-2023-24438)

  - Low JIRA Pipeline Steps Plugin 2.0.165.v8846cf59f3db and earlier stores the private key unencrypted in its
    global configuration file org.thoughtslive.jenkins.plugins.jira.JiraStepsConfig.xml on the Jenkins
    controller as part of its configuration. This key can be viewed by users with access to the Jenkins
    controller file system. Additionally, the global configuration form does not mask the API key, increasing
    the potential for attackers to observe and capture it. As of publication of this advisory, there is no
    fix. Learn why we announce this. (CVE-2023-24439, CVE-2023-24440)

  - Medium MSTest Plugin 1.0.0 and earlier does not configure its XML parser to prevent XML external entity
    (XXE) attacks. This allows attackers able to control the contents of the report file for the 'Publish
    MSTest test result report' post-build step to have agent processes parse a crafted file that uses external
    entities for extraction of secrets from the Jenkins agent or server-side request forgery. Because Jenkins
    agent processes usually execute build tools whose input (source code, build scripts, etc.) is controlled
    externally, this vulnerability only has a real impact in very narrow circumstances: when attackers can
    control XML files, but are unable to change build steps, Jenkinsfiles, test code that gets executed on the
    agents, or similar. As of publication of this advisory, there is no fix. Learn why we announce this.
    (CVE-2023-24441)

  - Low GitHub Pull Request Coverage Status Plugin 2.2.0 and earlier stores the GitHub Personal Access Token,
    Sonar access token and Sonar password unencrypted in its global configuration file
    com.github.terma.jenkins.githubprcoveragestatus.Configuration.xml on the Jenkins controller as part of its
    configuration. These credentials can be viewed by users with access to the Jenkins controller file system.
    As of publication of this advisory, there is no fix. Learn why we announce this. (CVE-2023-24442)

  - High Keycloak Authentication Plugin 2.3.0 and earlier does not invalidate the existing session on login.
    This allows attackers to use social engineering techniques to gain administrator access to Jenkins. As of
    publication of this advisory, there is no fix. Learn why we announce this. (CVE-2023-24456)

  - Medium Keycloak Authentication Plugin 2.3.0 and earlier does not implement a state parameter in its OAuth
    flow, a unique and non-guessable value associated with each authentication request. This vulnerability
    allows attackers to trick users into logging in to the attacker's account. As of publication of this
    advisory, there is no fix. Learn why we announce this. (CVE-2023-24457)

  - High TestComplete support Plugin 2.8.1 and earlier does not configure its XML parser to prevent XML
    external entity (XXE) attacks. This allows attackers able to control the zip archive input file for the
    'TestComplete Test' build step to have Jenkins parse a crafted file that uses external entities for
    extraction of secrets from the Jenkins controller or server-side request forgery. As of publication of
    this advisory, there is no fix. Learn why we announce this. (CVE-2023-24443)

  - High OpenID Plugin 2.4 and earlier does not invalidate the existing session on login. This allows
    attackers to use social engineering techniques to gain administrator access to Jenkins. As of publication
    of this advisory, there is no fix. Learn why we announce this. (CVE-2023-24444)

  - Medium OpenID Plugin 2.4 and earlier improperly determines that a redirect URL after login is legitimately
    pointing to Jenkins. This allows attackers to perform phishing attacks by having users go to a Jenkins URL
    that will forward them to a different site after successful authentication. As of publication of this
    advisory, there is no fix. Learn why we announce this. (CVE-2023-24445)

  - Medium OpenID Plugin 2.4 and earlier does not implement a state parameter in its OAuth flow, a unique and
    non-guessable value associated with each authentication request. This vulnerability allows attackers to
    trick users into logging in to the attacker's account. As of publication of this advisory, there is no
    fix. Learn why we announce this. (CVE-2023-24446)

  - Medium RabbitMQ Consumer Plugin 2.8 and earlier does not perform a permission check in a method
    implementing form validation. This allows attackers with Overall/Read permission to connect to an
    attacker-specified AMQP server using attacker-specified username and password. Additionally, this form
    validation method does not require POST requests, resulting in a cross-site request forgery (CSRF)
    vulnerability. As of publication of this advisory, there is no fix. Learn why we announce this.
    (CVE-2023-24447, CVE-2023-24448)

  - Medium PWauth Security Realm Plugin 0.4 and earlier does not restrict the names of files in methods
    implementing form validation. This allows attackers with Overall/Read permission to check for the
    existence of an attacker-specified file path on the Jenkins controller file system. As of publication of
    this advisory, there is no fix. Learn why we announce this. (CVE-2023-24449)

  - Medium view-cloner Plugin 1.1 and earlier stores passwords unencrypted in job config.xml files on the
    Jenkins controller as part of its configuration. These passwords can be viewed by users with Item/Extended
    Read permission or access to the Jenkins controller file system. As of publication of this advisory, there
    is no fix. Learn why we announce this. (CVE-2023-24450)

  - Medium Cisco Spark Notifier Plugin 1.1.1 and earlier does not perform permission checks in several HTTP
    endpoints. This allows attackers with Overall/Read permission to enumerate credentials IDs of credentials
    stored in Jenkins. Those can be used as part of an attack to capture the credentials using another
    vulnerability. As of publication of this advisory, there is no fix. Learn why we announce this.
    (CVE-2023-24451)

  - Medium BearyChat Plugin 3.0.2 and earlier does not perform a permission check in a method implementing
    form validation. This allows attackers with Overall/Read permission to connect to an attacker-specified
    URL. Additionally, this form validation method does not require POST requests, resulting in a cross-site
    request forgery (CSRF) vulnerability. As of publication of this advisory, there is no fix. Learn why we
    announce this. (CVE-2023-24458, CVE-2023-24459)

  - Medium TestQuality Updater Plugin 1.3 and earlier does not perform a permission check in a method
    implementing form validation. This allows attackers with Overall/Read permission to connect to an
    attacker-specified URL using attacker-specified username and password. Additionally, this form validation
    method does not require POST requests, resulting in a cross-site request forgery (CSRF) vulnerability. As
    of publication of this advisory, there is no fix. Learn why we announce this. (CVE-2023-24452,
    CVE-2023-24453)

  - Low TestQuality Updater Plugin 1.3 and earlier stores the TestQuality Updater password unencrypted in its
    global configuration file com.testquality.jenkins.TestQualityNotifier.xml on the Jenkins controller as
    part of its configuration. This password can be viewed by users with access to the Jenkins controller file
    system. As of publication of this advisory, there is no fix. Learn why we announce this. (CVE-2023-24454)

  - Medium visualexpert Plugin 1.3 and earlier does not restrict the names of files in methods implementing
    form validation. This allows attackers with Item/Configure permission to check for the existence of an
    attacker-specified file path on the Jenkins controller file system. As of publication of this advisory,
    there is no fix. Learn why we announce this. (CVE-2023-24455)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2023-01-24");
  script_set_attribute(attribute:"solution", value:
"Update Jenkins plugins to the following versions:
  - Azure AD Plugin to version 306.va_7083923fd50 or later
  - BearyChat Plugin: See vendor advisory
  - Bitbucket OAuth Plugin to version 0.13 or later
  - Cisco Spark Notifier Plugin: See vendor advisory
  - Gerrit Trigger Plugin to version 2.38.1 or later
  - GitHub Pull Request Builder Plugin: See vendor advisory
  - GitHub Pull Request Coverage Status Plugin: See vendor advisory
  - JIRA Pipeline Steps Plugin: See vendor advisory
  - Keycloak Authentication Plugin: See vendor advisory
  - Kubernetes Credentials Provider Plugin to version 1.209.v862c6e5fb_1ef or later
  - MSTest Plugin: See vendor advisory
  - OpenId Connect Authentication Plugin to version 2.5 or later
  - OpenID Plugin: See vendor advisory
  - Orka by MacStadium Plugin to version 1.32 or later
  - PWauth Security Realm Plugin: See vendor advisory
  - RabbitMQ Consumer Plugin: See vendor advisory
  - Script Security Plugin to version 1229.v4880b_b_e905a_6 or later
  - Semantic Versioning Plugin to version 1.15 or later
  - TestComplete support Plugin: See vendor advisory
  - TestQuality Updater Plugin: See vendor advisory
  - view-cloner Plugin: See vendor advisory
  - visualexpert Plugin: See vendor advisory

See vendor advisory for more details.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24458");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_plugins_detect.nbin", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');
include('jenkins_plugin_mappings.inc');

var constraints = [
    {'max_version' : '303', 'fixed_version' : '306', 'fixed_display' : '306.va_7083923fd50', 'plugin' : jenkins_plugin_mappings['Azure AD Plugin']},
    {'max_version' : '3.0.2', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['BearyChat Plugin']},
    {'max_version' : '0.12', 'fixed_version' : '0.13', 'plugin' : jenkins_plugin_mappings['Bitbucket OAuth Plugin']},
    {'max_version' : '1.1.1', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['Cisco Spark Notifier Plugin']},
    {'max_version' : '2.38.0', 'fixed_version' : '2.38.1', 'plugin' : jenkins_plugin_mappings['Gerrit Trigger Plugin']},
    {'max_version' : '1.42.2', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['GitHub Pull Request Builder Plugin']},
    {'max_version' : '2.2.0', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['GitHub Pull Request Coverage Status Plugin']},
    {'max_version' : '2.0.165', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['JIRA Pipeline Steps Plugin']},
    {'max_version' : '2.3.0', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['Keycloak Authentication Plugin']},
    {'max_version' : '1.208', 'fixed_version' : '1.209', 'fixed_display' : '1.209.v862c6e5fb_1ef', 'plugin' : jenkins_plugin_mappings['Kubernetes Credentials Provider Plugin']},
    {'max_version' : '1.0.0', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['MSTest Plugin']},
    {'max_version' : '2.4', 'fixed_version' : '2.5', 'plugin' : jenkins_plugin_mappings['OpenId Connect Authentication Plugin']},
    {'max_version' : '2.4', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['OpenID Plugin']},
    {'max_version' : '1.31', 'fixed_version' : '1.32', 'plugin' : jenkins_plugin_mappings['Orka by MacStadium Plugin']},
    {'max_version' : '0.4', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['PWauth Security Realm Plugin']},
    {'max_version' : '2.8', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['RabbitMQ Consumer Plugin']},
    {'max_version' : '1228', 'fixed_version' : '1229', 'fixed_display' : '1229.v4880b_b_e905a_6', 'plugin' : jenkins_plugin_mappings['Script Security Plugin']},
    {'max_version' : '1.14', 'fixed_version' : '1.15', 'plugin' : jenkins_plugin_mappings['Semantic Versioning Plugin']},
    {'max_version' : '2.8.1', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['TestComplete support Plugin']},
    {'max_version' : '1.3', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['TestQuality Updater Plugin']},
    {'max_version' : '1.1', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['view-cloner Plugin']},
    {'max_version' : '1.3', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['visualexpert Plugin']}
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:constraints);

vcf::jenkins::plugin::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xsrf':TRUE}
);
