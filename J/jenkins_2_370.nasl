#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165766);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/01");

  script_cve_id(
    "CVE-2022-41224",
    "CVE-2022-41225",
    "CVE-2022-41226",
    "CVE-2022-41227",
    "CVE-2022-41228",
    "CVE-2022-41229",
    "CVE-2022-41230",
    "CVE-2022-41231",
    "CVE-2022-41232",
    "CVE-2022-41233",
    "CVE-2022-41234",
    "CVE-2022-41235",
    "CVE-2022-41236",
    "CVE-2022-41237",
    "CVE-2022-41238",
    "CVE-2022-41239",
    "CVE-2022-41240",
    "CVE-2022-41241",
    "CVE-2022-41242",
    "CVE-2022-41243",
    "CVE-2022-41244",
    "CVE-2022-41245",
    "CVE-2022-41246",
    "CVE-2022-41247",
    "CVE-2022-41248",
    "CVE-2022-41249",
    "CVE-2022-41250",
    "CVE-2022-41251",
    "CVE-2022-41252",
    "CVE-2022-41253",
    "CVE-2022-41254",
    "CVE-2022-41255"
  );

  script_name(english:"Jenkins weekly < 2.370 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its its self-reported version number, the version of Jenkins running on the remote web server is Jenkins
weekly prior to 2.370. It is, therefore, affected by multiple vulnerabilities:

  - Jenkins 2.367 through 2.369 (both inclusive) does not escape tooltips of the l:helpIcon UI component used
    for some help icons on the Jenkins web UI, resulting in a stored cross-site scripting (XSS) vulnerability
    exploitable by attackers able to control tooltips for this component. (CVE-2022-41224)

  - Jenkins Anchore Container Image Scanner Plugin 1.0.24 and earlier does not escape content provided by the
    Anchore engine API, resulting in a stored cross-site scripting (XSS) vulnerability exploitable by
    attackers able to control API responses by Anchore engine. (CVE-2022-41225)

  - Jenkins Compuware Common Configuration Plugin 1.0.14 and earlier does not configure its XML parser to
    prevent XML external entity (XXE) attacks. (CVE-2022-41226)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins NS-ND Integration Performance Publisher
    Plugin 4.8.0.129 and earlier allows attackers to connect to an attacker-specified webserver using
    attacker-specified credentials. (CVE-2022-41227)

  - A missing permission check in Jenkins NS-ND Integration Performance Publisher Plugin 4.8.0.129 and earlier
    allows attackers with Overall/Read permissions to connect to an attacker-specified webserver using
    attacker-specified credentials. (CVE-2022-41228)

  - Jenkins NS-ND Integration Performance Publisher Plugin 4.8.0.134 and earlier does not escape configuration
    options of the Execute NetStorm/NetCloud Test build step, resulting in a stored cross-site scripting (XSS)
    vulnerability exploitable by attackers with Item/Configure permission. (CVE-2022-41229)

  - Jenkins Build-Publisher Plugin 1.22 and earlier does not perform a permission check in an HTTP endpoint,
    allowing attackers with Overall/Read permission to obtain names and URLs of Jenkins servers that the
    plugin is configured to publish builds to, as well as builds pending for publication to those Jenkins
    servers. (CVE-2022-41230)

  - Jenkins Build-Publisher Plugin 1.22 and earlier allows attackers with Item/Configure permission to create
    or replace any config.xml file on the Jenkins controller file system by providing a crafted file name to
    an API endpoint. (CVE-2022-41231)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Build-Publisher Plugin 1.22 and earlier
    allows attackers to replace any config.xml file on the Jenkins controller file system with an empty file
    by providing a crafted file name to an API endpoint. (CVE-2022-41232)

  - Jenkins Rundeck Plugin 3.6.11 and earlier does not perform Run/Artifacts permission checks in multiple
    HTTP endpoints, allowing attackers with Item/Read permission to obtain information about build artifacts
    of a given job, if the optional Run/Artifacts permission is enabled. (CVE-2022-41233)

  - Jenkins Rundeck Plugin 3.6.11 and earlier does not protect access to the /plugin/rundeck/webhook/
    endpoint, allowing users with Overall/Read permission to trigger jobs that are configured to be
    triggerable via Rundeck. (CVE-2022-41234)

  - Jenkins WildFly Deployer Plugin 1.0.2 and earlier implements functionality that allows agent processes to
    read arbitrary files on the Jenkins controller file system. (CVE-2022-41235)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Security Inspector Plugin 117.v6eecc36919c2
    and earlier allows attackers to replace the generated report stored in a per-session cache and displayed
    to authorized users at the .../report URL with a report based on attacker-specified report generation
    options. (CVE-2022-41236)

  - Jenkins DotCi Plugin 2.40.00 and earlier does not configure its YAML parser to prevent the instantiation
    of arbitrary types, resulting in a remote code execution vulnerability. (CVE-2022-41237)

  - A missing permission check in Jenkins DotCi Plugin 2.40.00 and earlier allows unauthenticated attackers to
    trigger builds of jobs corresponding to the attacker-specified repository for attacker-specified commits.
    (CVE-2022-41238)

  - Jenkins DotCi Plugin 2.40.00 and earlier does not escape the GitHub user name parameter provided to commit
    notifications when displaying them in a build cause, resulting in a stored cross-site scripting (XSS)
    vulnerability. (CVE-2022-41239)

  - Jenkins Walti Plugin 1.0.1 and earlier does not escape the information provided by the Walti API,
    resulting in a stored cross-site scripting (XSS) vulnerability exploitable by attackers able to provide
    malicious API responses from Walti. (CVE-2022-41240)

  - Jenkins RQM Plugin 2.8 and earlier does not configure its XML parser to prevent XML external entity (XXE)
    attacks. (CVE-2022-41241)

  - A missing permission check in Jenkins extreme-feedback Plugin 1.7 and earlier allows attackers with
    Overall/Read permission to discover information about job names attached to lamps, discover MAC and IP
    addresses of existing lamps, and rename lamps. (CVE-2022-41242)

  - Jenkins SmallTest Plugin 1.0.4 and earlier does not perform hostname validation when connecting to the
    configured View26 server that could be abused using a man-in-the-middle attack to intercept these
    connections. (CVE-2022-41243)

  - Jenkins View26 Test-Reporting Plugin 1.0.7 and earlier does not perform hostname validation when
    connecting to the configured View26 server that could be abused using a man-in-the-middle attack to
    intercept these connections. (CVE-2022-41244)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Worksoft Execution Manager Plugin 10.0.3.503
    and earlier allows attackers to connect to an attacker-specified URL using attacker-specified credentials
    IDs obtained through another method, capturing credentials stored in Jenkins. (CVE-2022-41245)

  - A missing permission check in Jenkins Worksoft Execution Manager Plugin 10.0.3.503 and earlier allows
    attackers with Overall/Read permission to connect to an attacker-specified URL using attacker-specified
    credentials IDs obtained through another method, capturing credentials stored in Jenkins. (CVE-2022-41246)

  - Jenkins BigPanda Notifier Plugin 1.4.0 and earlier stores the BigPanda API key unencrypted in its global
    configuration file on the Jenkins controller where they can be viewed by users with access to the Jenkins
    controller file system. (CVE-2022-41247)

  - Jenkins BigPanda Notifier Plugin 1.4.0 and earlier does not mask the BigPanda API key on the global
    configuration form, increasing the potential for attackers to observe and capture it. (CVE-2022-41248)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins SCM HttpClient Plugin 1.5 and earlier allows
    attackers to connect to an attacker-specified HTTP server using attacker-specified credentials IDs
    obtained through another method, capturing credentials stored in Jenkins. (CVE-2022-41249)

  - A missing permission check in Jenkins SCM HttpClient Plugin 1.5 and earlier allows attackers with
    Overall/Read permission to connect to an attacker-specified HTTP server using attacker-specified
    credentials IDs obtained through another method, capturing credentials stored in Jenkins. (CVE-2022-41250)

  - A missing permission check in Jenkins Apprenda Plugin 2.2.0 and earlier allows users with Overall/Read
    permission to enumerate credentials IDs of credentials stored in Jenkins. (CVE-2022-41251)

  - Missing permission checks in Jenkins CONS3RT Plugin 1.0.0 and earlier allows users with Overall/Read
    permission to enumerate credentials ID of credentials stored in Jenkins. (CVE-2022-41252)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins CONS3RT Plugin 1.0.0 and earlier allows
    attackers to connect to an attacker-specified HTTP server using attacker-specified credentials IDs
    obtained through another method, capturing credentials stored in Jenkins. (CVE-2022-41253)

  - Missing permission checks in Jenkins CONS3RT Plugin 1.0.0 and earlier allow attackers with Overall/Read
    permission to connect to an attacker-specified HTTP server using attacker-specified credentials IDs
    obtained through another method, capturing credentials stored in Jenkins. (CVE-2022-41254)

  - Jenkins CONS3RT Plugin 1.0.0 and earlier stores Cons3rt API token unencrypted in job config.xml files on
    the Jenkins controller where it can be viewed by users with access to the Jenkins controller file system.
    (CVE-2022-41255)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2022-09-21");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins weekly to version 2.370 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41253");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-41238");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var constraints = [
  { 'max_version' : '2.369', 'fixed_version' : '2.370', 'edition' : 'Open Source' }
];

var app_info = vcf::combined_get_app_info(app:'Jenkins');

vcf::jenkins::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xsrf':TRUE, 'xss':TRUE}
);
