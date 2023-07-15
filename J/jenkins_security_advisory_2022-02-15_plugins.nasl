##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162138);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/14");

  script_cve_id(
    "CVE-2022-25173",
    "CVE-2022-25174",
    "CVE-2022-25175",
    "CVE-2022-25176",
    "CVE-2022-25177",
    "CVE-2022-25178",
    "CVE-2022-25179",
    "CVE-2022-25180",
    "CVE-2022-25181",
    "CVE-2022-25182",
    "CVE-2022-25183",
    "CVE-2022-25184",
    "CVE-2022-25185",
    "CVE-2022-25186",
    "CVE-2022-25187",
    "CVE-2022-25188",
    "CVE-2022-25189",
    "CVE-2022-25190",
    "CVE-2022-25191",
    "CVE-2022-25192",
    "CVE-2022-25193",
    "CVE-2022-25194",
    "CVE-2022-25195",
    "CVE-2022-25196",
    "CVE-2022-25197",
    "CVE-2022-25198",
    "CVE-2022-25199",
    "CVE-2022-25200",
    "CVE-2022-25201",
    "CVE-2022-25202",
    "CVE-2022-25203",
    "CVE-2022-25204",
    "CVE-2022-25205",
    "CVE-2022-25206",
    "CVE-2022-25207",
    "CVE-2022-25208",
    "CVE-2022-25209",
    "CVE-2022-25210",
    "CVE-2022-25211",
    "CVE-2022-25212"
  );

  script_name(english:"Jenkins plugins Multiple Vulnerabilities (2022-02-15)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to their self-reported version numbers, the version of Jenkins plugins running on the remote web server are
affected by multiple vulnerabilities:

  - Multiple Pipeline-related plugins that perform on-controller SCM checkouts reuse the same workspace
    directory for checkouts of distinct SCMs in some contexts. Pipeline: Groovy Plugin 2648.va9433432b33c and
    earlier uses the same checkout directories for distinct SCMs when reading the script file (typically
    Jenkinsfile) for Pipelines. Pipeline: Shared Groovy Libraries 552.vd9cc05b8a2e1 and earlier uses the same
    checkout directories for distinct SCMs for Pipeline libraries. Pipeline: Multibranch 706.vd43c65dec013 and
    earlier uses the same checkout directories for distinct SCMs for the readTrusted step. This allows
    attackers with Item/Configure permission to invoke arbitrary OS commands on the controller through crafted
    SCM contents. Affected plugins have been updated to address these issues: Pipeline: Groovy Plugin
    2656.vf7a_e7b_75a_457 uses distinct checkout directories per SCM when reading the script file (typically
    Jenkinsfile) for Pipelines. Pipeline: Shared Groovy Libraries 561.va_ce0de3c2d69 uses distinct checkout
    directories per SCM for Pipeline libraries. Pipeline: Multibranch 707.v71c3f0a_6ccdb_ uses distinct
    checkout directories per SCM for the readTrusted step. (CVE-2022-25173, CVE-2022-25174, CVE-2022-25175)

  - Multiple Pipeline-related plugins follow symbolic links or do not limit path names, resulting in arbitrary
    file read vulnerabilities: Pipeline: Groovy Plugin 2648.va9433432b33c and earlier follows symbolic links
    to locations outside of the checkout directory for the configured SCM when reading the script file
    (typically Jenkinsfile) for Pipelines (originally reported as SECURITY-2595). Pipeline: Shared Groovy
    Libraries 552.vd9cc05b8a2e1 and earlier follows symbolic links to locations outside of the expected
    Pipeline library when reading files using the libraryResource step (originally reported as SECURITY-2479).
    Pipeline: Shared Groovy Libraries 552.vd9cc05b8a2e1 and earlier does not restrict the names of resources
    passed to the libraryResource step (originally reported as SECURITY-2476). Pipeline: Multibranch
    706.vd43c65dec013 and earlier follows symbolic links to locations outside of the checkout directory for
    the configured SCM when reading files using the readTrusted step (originally reported as SECURITY-2491).
    This allows attackers able to configure Pipelines to read arbitrary files on the Jenkins controller file
    system. Affected plugins have been updated to address these issues: Pipeline: Groovy Plugin
    2656.vf7a_e7b_75a_457 checks that the script file for Pipelines is inside of the checkout directory for
    the configured SCM. Pipeline: Shared Groovy Libraries 561.va_ce0de3c2d69 checks that any resources
    retrieved by the libraryResource step are contained within the expected Pipeline library. Pipeline:
    Multibranch 707.v71c3f0a_6ccdb_ checks that the file retrieved by readTrusted is inside of the checkout
    directory for the configured SCM. (CVE-2022-25176, CVE-2022-25177, CVE-2022-25178, CVE-2022-25179)

  - Pipeline: Groovy Plugin 2648.va9433432b33c and earlier includes password parameters from the original
    build in replayed builds. This allows attackers with Run/Replay permission to obtain the values of
    password parameters passed to previous builds of a Pipeline. Pipeline: Groovy Plugin 2656.vf7a_e7b_75a_457
    does not allow builds containing password parameters to be replayed. (CVE-2022-25180)

  - Pipeline: Deprecated Groovy Libraries Plugin 552.vd9cc05b8a2e1 and earlier uses the same workspace
    directory for all checkouts of Pipeline libraries with the same name regardless of the SCM being used and
    the source of the library configuration. This allows attackers with Item/Configure permission to execute
    arbitrary code in the context of the Jenkins controller JVM through crafted SCM contents, if a global
    Pipeline library already exists. Pipeline: Deprecated Groovy Libraries Plugin 561.va_ce0de3c2d69 uses
    distinct checkout directories per SCM for Pipeline libraries. (CVE-2022-25181)

  - Pipeline: Deprecated Groovy Libraries Plugin 552.vd9cc05b8a2e1 and earlier uses the names of Pipeline
    libraries to create directories without canonicalization or sanitization. This allows attackers with
    Item/Configure permission to execute arbitrary code in the context of the Jenkins controller JVM using
    specially crafted library names if a global Pipeline library is already configured. Pipeline: Deprecated
    Groovy Libraries Plugin 561.va_ce0de3c2d69 sanitizes the names of Pipeline libraries when creating library
    directories. (CVE-2022-25182)

  - Pipeline: Deprecated Groovy Libraries Plugin 552.vd9cc05b8a2e1 and earlier uses the names of Pipeline
    libraries to create cache directories without any sanitization. This allows attackers with Item/Configure
    permission to execute arbitrary code in the context of the Jenkins controller JVM using specially crafted
    library names if a global Pipeline library configured to use caching already exists. Pipeline: Deprecated
    Groovy Libraries Plugin 561.va_ce0de3c2d69 sanitizes the names of Pipeline libraries when creating library
    cache directories. (CVE-2022-25183)

  - Pipeline: Build Step Plugin 2.15 and earlier reveals password parameter default values when generating a
    pipeline script using the Pipeline Snippet Generator. This allows attackers with Item/Read permission to
    retrieve the default password parameter value from jobs. Pipeline: Build Step Plugin 2.15.1 redacts
    password parameter in the generated pipeline script. (CVE-2022-25184)

  - Generic Webhook Trigger Plugin 1.81 and earlier does not escape the build cause for the webhook. This
    results in a stored cross-site scripting (XSS) vulnerability exploitable by attackers able to trigger
    builds using the webhook. Generic Webhook Trigger Plugin 1.82 escapes the build cause when displayed on
    the UI. Note This vulnerability is only exploitable in Jenkins 2.314 and earlier, LTS 2.303.1 and earlier.
    See the LTS upgrade guide. (CVE-2022-25185)

  - HashiCorp Vault Plugin 3.8.0 and earlier implements functionality that allows agent processes to retrieve
    any Vault secrets for use on the agent. This allows attackers able to control agent processes to obtain
    Vault secrets for an attacker-specified path and key. The functionality that allow agent processes to
    capture Vault secret can no longer be used in HashiCorp Vault Plugin 336.v182c0fbaaeb7. (CVE-2022-25186)

  - Support Core Plugin has a feature to redact potentially sensitive information in the support bundle.
    Support Core Plugin 2.79 and earlier does not redact some sensitive information in the support bundle.
    This sensitive information can be viewed by anyone with access to the bundle. Support Core Plugin 2.79.1
    adds a list of keywords whose associated values will be redacted. This list is stored in the security-
    stop-words.txt file located in $JENKINS_HOME/support and can be amended to add additional keywords for
    values that should be redacted. (CVE-2022-25187)

  - Fortify Plugin 20.2.34 and earlier does not sanitize the appName and appVersion parameters of its Pipeline
    steps, which are used to write to files inside build directories. This allows attackers with
    Item/Configure permission to write or overwrite .xml files on the Jenkins controller file system with
    content not controllable by the attacker. Fortify Plugin 20.2.35 sanitizes the appName and appVersion
    parameters of its Pipeline steps when determining the resulting filename. (CVE-2022-25188)

  - Custom Checkbox Parameter Plugin 1.1 and earlier does not escape parameter names of custom checkbox
    parameters. This results in a stored cross-site scripting (XSS) vulnerability exploitable by attackers
    with Item/Configure permission. Custom Checkbox Parameter Plugin 1.2 escapes parameter names of custom
    checkbox parameters. (CVE-2022-25189)

  - Conjur Secrets Plugin 1.0.11 and earlier does not perform a permission check in an HTTP endpoint. This
    allows attackers with Overall/Read permission to enumerate credentials IDs of credentials stored in
    Jenkins. Those can be used as part of an attack to capture the credentials using another vulnerability. An
    enumeration of credentials IDs in Conjur Secrets Plugin 1.0.12 requires Overall/Administer permission.
    (CVE-2022-25190)

  - Agent Server Parameter Plugin 1.0 and earlier does not escape parameter names of agent server parameters.
    This results in a stored cross-site scripting (XSS) vulnerability exploitable by attackers with
    Item/Configure permission. Agent Server Parameter Plugin 1.1 escapes parameter names of agent server
    parameters. (CVE-2022-25191)

  - Snow Commander Plugin 2.0 and earlier does not perform permission checks in methods implementing form
    validation. This allows attackers with Overall/Read permission to connect to an attacker-specified
    webserver using attacker-specified credentials IDs obtained through another method, capturing credentials
    stored in Jenkins. Additionally, these form validation methods do not require POST requests, resulting in
    a cross-site request forgery (CSRF) vulnerability. Snow Commander Plugin 2.0 requires POST requests and
    Overall/Administer permission for the affected form validation methods. (CVE-2022-25192, CVE-2022-25193)

  - autonomiq Plugin 1.15 and earlier does not perform a permission check in an HTTP endpoint. This allows
    attackers with Overall/Read permission to connect to an attacker-specified URL using attacker-specified
    username and password. Additionally, this HTTP endpoint does not require POST requests, resulting in a
    cross-site request forgery (CSRF) vulnerability. autonomiq Plugin 1.16 requires POST requests and
    Overall/Administer permission for this HTTP endpoint. (CVE-2022-25194, CVE-2022-25195)

  - GitLab Authentication Plugin 1.13 and earlier records the HTTP Referer header as part of the URL query
    parameters when the authentication process starts and redirects users to that URL when the user has
    finished logging in. This allows attackers with access to Jenkins to craft a URL that will redirect users
    to an attacker-specified URL after logging in. Note This issue is caused by an incomplete fix of
    SECURITY-796. As of publication of this advisory, there is no fix. (CVE-2022-25196)

  - HashiCorp Vault Plugin 336.v182c0fbaaeb7 and earlier implements functionality that allows agent processes
    to read arbitrary files on the Jenkins controller file system. This allows attackers able to control agent
    processes to read arbitrary files on the Jenkins controller file system. Note This vulnerability is only
    exploitable in Jenkins 2.318 and earlier, LTS 2.303.2 and earlier. See the LTS upgrade guide. As of
    publication of this advisory, there is no fix. (CVE-2022-25197)

  - SCP publisher Plugin 1.8 and earlier does not perform a permission check in a method implementing form
    validation. This allows attackers with Overall/Read permission to connect to an attacker-specified SSH
    server using attacker-specified username and password. Additionally, this form validation method does not
    require POST requests, resulting in a cross-site request forgery (CSRF) vulnerability. As of publication
    of this advisory, there is no fix. (CVE-2022-25198, CVE-2022-25199)

  - Checkmarx Plugin 2022.1.2 and earlier does not perform permission checks in several HTTP endpoints. This
    allows attackers with Overall/Read permission to connect to an attacker-specified webserver using
    attacker-specified credentials IDs obtained through another method, capturing credentials stored in
    Jenkins. Additionally, these HTTP endpoints do not require POST requests, resulting in a cross-site
    request forgery (CSRF) vulnerability. As of publication of this advisory, there is no fix.
    (CVE-2022-25200, CVE-2022-25201)

  - Promoted Builds (Simple) Plugin 1.9 and earlier does not escape the name of custom promotion levels. This
    results in a stored cross-site scripting (XSS) vulnerability exploitable by attackers with
    Overall/Administer permission. As of publication of this advisory, there is no fix. (CVE-2022-25202)

  - Team Views Plugin 0.9.0 and earlier does not escape team names. This results in a stored cross-site
    scripting (XSS) vulnerability exploitable by attackers with Overall/Read permission. As of publication of
    this advisory, there is no fix. (CVE-2022-25203)

  - Doktor Plugin 0.4.1 and earlier implements functionality that allows agent processes to render files on
    the controller as Markdown or Asciidoc. Additionally, error messages allow attackers able to control agent
    processes to determine whether a file with a given name exists. As of publication of this advisory, there
    is no fix. (CVE-2022-25204)

  - dbCharts Plugin 0.5.2 and earlier does not perform a permission check in a method implementing form
    validation. This allows attackers with Overall/Read permission to connect to an attacker-specified
    database via JDBC using attacker-specified credentials. Additionally, this method allows attackers to
    determine whether a class is available on the Jenkins controller's class path through error messages.
    Additionally, this form validation method does not require POST requests, resulting in a cross-site
    request forgery (CSRF) vulnerability. As of publication of this advisory, there is no fix.
    (CVE-2022-25205, CVE-2022-25206)

  - Chef Sinatra Plugin 1.20 and earlier does not perform a permission check in a method implementing form
    validation. This allows attackers with Overall/Read permission to have Jenkins send an HTTP request to an
    attacker-controlled URL and have it parse the response as XML. As the plugin does not configure its XML
    parser to prevent XML external entity (XXE) attacks, attackers can have Jenkins parse a crafted XML
    response that uses external entities for extraction of secrets from the Jenkins controller or server-side
    request forgery. Additionally, this form validation method does not require POST requests, resulting in a
    cross-site request forgery (CSRF) vulnerability. As of publication of this advisory, there is no fix.
    (CVE-2022-25207, CVE-2022-25208, CVE-2022-25209)

  - Convertigo Mobile Platform Plugin 1.1 and earlier uses static fields to store job configuration
    information. This allows attackers with Item/Configure permission to capture passwords of the jobs that
    will be configured. As of publication of this advisory, there is no fix. (CVE-2022-25210)

  - SWAMP Plugin 1.2.6 and earlier does not perform a permission check in a method implementing form
    validation. This allows attackers with Overall/Read permission to connect to an attacker-specified URL
    using attacker-specified credentials IDs obtained through another method, capturing credentials stored in
    Jenkins. Additionally, this form validation method does not require POST requests, resulting in a cross-
    site request forgery (CSRF) vulnerability. As of publication of this advisory, there is no fix.
    (CVE-2022-25211, CVE-2022-25212)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2022-02-15");
  script_set_attribute(attribute:"solution", value:
"Update Jenkins plugins to the following versions:
  - Agent Server Parameter Plugin to version 1.1 or later
  - autonomiq Plugin to version 1.16 or later
  - Conjur Secrets Plugin to version 1.0.12 or later
  - Custom Checkbox Parameter Plugin to version 1.2 or later
  - Fortify Plugin to version 20.2.35 or later
  - Generic Webhook Trigger Plugin to version 1.82 or later
  - HashiCorp Vault Plugin to version 336 or later
  - Pipeline: Build Step Plugin to version 2.15.1 or later
  - Pipeline: Deprecated Groovy Libraries Plugin to version 561 or later
  - Pipeline: Groovy Plugin to version 2656 or later
  - Pipeline: Multibranch Plugin to version 707 or later
  - Snow Commander Plugin to version 2.0 or later
  - Support Core Plugin to version 2.79.1 or later

See vendor advisory for more details.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-25212");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_plugins_detect.nbin", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');
include('jenkins_plugin_mappings.inc');

var constraints = [
    {'max_version' : '1.0', 'fixed_version' : '1.1', 'plugin' : jenkins_plugin_mappings['Agent Server Parameter Plugin']},
    {'max_version' : '1.15', 'fixed_version' : '1.16', 'plugin' : jenkins_plugin_mappings['autonomiq Plugin']},
    {'max_version' : '2022.1.2', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['Checkmarx Plugin']},
    {'max_version' : '1.20', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['Chef Sinatra Plugin']},
    {'max_version' : '1.0.11', 'fixed_version' : '1.0.12', 'plugin' : jenkins_plugin_mappings['Conjur Secrets Plugin']},
    {'max_version' : '1.1', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['Convertigo Mobile Platform Plugin']},
    {'max_version' : '1.1', 'fixed_version' : '1.2', 'plugin' : jenkins_plugin_mappings['Custom Checkbox Parameter Plugin']},
    {'max_version' : '0.5.2', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['dbCharts Plugin']},
    {'max_version' : '0.4.1', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['Doktor Plugin']},
    {'max_version' : '20.2.34', 'fixed_version' : '20.2.35', 'plugin' : jenkins_plugin_mappings['Fortify Plugin']},
    {'max_version' : '1.81', 'fixed_version' : '1.82', 'plugin' : jenkins_plugin_mappings['Generic Webhook Trigger Plugin']},
    {'max_version' : '1.13', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['GitLab Authentication Plugin']},
    {'min_version' : '3.8.0', 'fixed_version' : '336', 'fixed_display' : '336.v182c0fbaaeb7', 'plugin' : jenkins_plugin_mappings['HashiCorp Vault Plugin']},
    {'max_version' : '2.15', 'fixed_version' : '2.15.1', 'plugin' : jenkins_plugin_mappings['Pipeline: Build Step Plugin']},
    # Advisory intially said "Shared Groovy Libraries" but has been updated to "Deprecated Groovy Libraries". Constraint needed for both
    {'max_version' : '552', 'fixed_version' : '561', 'fixed_display' : '561.va_ce0de3c2d69', 'plugin' : jenkins_plugin_mappings['Pipeline: Deprecated Groovy Libraries Plugin']},
    {'max_version' : '552', 'fixed_version' : '561', 'fixed_display' : '561.va_ce0de3c2d69', 'plugin' : jenkins_plugin_mappings['Pipeline: Shared Groovy Libraries Plugin']},
    {'max_version' : '2648', 'fixed_version' : '2656', 'fixed_display' : '2656.vf7a_e7b_75a_457', 'plugin' : jenkins_plugin_mappings['Pipeline: Groovy Plugin']},
    {'max_version' : '706', 'fixed_version' : '707', 'fixed_display' : '707.v71c3f0a_6ccdb_', 'plugin' : jenkins_plugin_mappings['Pipeline: Multibranch Plugin']},
    {'max_version' : '1.9', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['Promoted Builds (Simple) Plugin']},
    {'max_version' : '1.8', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['SCP publisher Plugin']},
    # Advisory lists 2.0 as both affected and fixed
    {'max_version' : '2.0', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['Snow Commander Plugin']},
    {'max_version' : '2.79', 'fixed_version' : '2.79.1', 'plugin' : jenkins_plugin_mappings['Support Core Plugin']},
    {'max_version' : '1.2.6', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['SWAMP Plugin']},
    {'max_version' : '0.9.0', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['Team Views Plugin']}
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:constraints);

vcf::jenkins::plugin::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xsrf':TRUE, 'xss':TRUE}
);
