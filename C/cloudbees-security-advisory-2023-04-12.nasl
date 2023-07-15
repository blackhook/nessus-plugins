#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174253);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/13");

  script_cve_id(
    "CVE-2023-30513",
    "CVE-2023-30514",
    "CVE-2023-30515",
    "CVE-2023-30516",
    "CVE-2023-30517",
    "CVE-2023-30518",
    "CVE-2023-30519",
    "CVE-2023-30520",
    "CVE-2023-30521",
    "CVE-2023-30522",
    "CVE-2023-30523",
    "CVE-2023-30524",
    "CVE-2023-30525",
    "CVE-2023-30526",
    "CVE-2023-30527",
    "CVE-2023-30528",
    "CVE-2023-30529",
    "CVE-2023-30530",
    "CVE-2023-30531",
    "CVE-2023-30532"
  );

  script_name(english:"Jenkins Enterprise and Operations Center 2.346.x < 2.346.40.0.15 Multiple Vulnerabilities (CloudBees Security Advisory 2023-04-12)");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins Enterprise or Jenkins Operations Center running on the remote web server is 2.346.x prior to
2.346.40.0.15. It is, therefore, affected by multiple vulnerabilities including the following:

  - Jenkins Kubernetes Plugin 3909.v1f2c633e8590 and earlier does not properly mask (i.e., replace with
    asterisks) credentials in the build log when push mode for durable task logging is enabled.
    (CVE-2023-30513)

  - Jenkins Azure Key Vault Plugin 187.va_cd5fecd198a_ and earlier does not properly mask (i.e., replace with
    asterisks) credentials in the build log when push mode for durable task logging is enabled.
    (CVE-2023-30514)

  - Jenkins Thycotic DevOps Secrets Vault Plugin 1.0.0 and earlier does not properly mask (i.e., replace with
    asterisks) credentials in the build log when push mode for durable task logging is enabled.
    (CVE-2023-30515)

  - Jenkins Image Tag Parameter Plugin 2.0 improperly introduces an option to opt out of SSL/TLS certificate
    validation when connecting to Docker registries, resulting in job configurations using Image Tag
    Parameters that were created before 2.0 having SSL/TLS certificate validation disabled by default.
    (CVE-2023-30516)

  - Jenkins NeuVector Vulnerability Scanner Plugin 1.22 and earlier unconditionally disables SSL/TLS
    certificate and hostname validation when connecting to a configured NeuVector Vulnerability Scanner
    server. (CVE-2023-30517)

  - A missing permission check in Jenkins Thycotic Secret Server Plugin 1.0.2 and earlier allows attackers
    with Overall/Read permission to enumerate credentials IDs of credentials stored in Jenkins.
    (CVE-2023-30518)

  - A missing permission check in Jenkins Quay.io trigger Plugin 0.1 and earlier allows unauthenticated
    attackers to trigger builds of jobs corresponding to the attacker-specified repository. (CVE-2023-30519)

  - Jenkins Quay.io trigger Plugin 0.1 and earlier does not limit URL schemes for repository homepage URLs
    submitted via Quay.io trigger webhooks, resulting in a stored cross-site scripting (XSS) vulnerability
    exploitable by attackers able to submit crafted Quay.io trigger webhook payloads. (CVE-2023-30520)

  - A missing permission check in Jenkins Assembla merge request builder Plugin 1.1.13 and earlier allows
    unauthenticated attackers to trigger builds of jobs corresponding to the attacker-specified repository.
    (CVE-2023-30521)

  - A missing permission check in Jenkins Fogbugz Plugin 2.2.17 and earlier allows attackers with Item/Read
    permission to trigger builds of jobs specified in a 'jobname' request parameter. (CVE-2023-30522)

  - Jenkins Report Portal Plugin 0.5 and earlier stores ReportPortal access tokens unencrypted in job
    config.xml files on the Jenkins controller as part of its configuration where they can be viewed by users
    with Item/Extended Read permission or access to the Jenkins controller file system. (CVE-2023-30523)

  - Jenkins Report Portal Plugin 0.5 and earlier does not mask ReportPortal access tokens displayed on the
    configuration form, increasing the potential for attackers to observe and capture them. (CVE-2023-30524)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Report Portal Plugin 0.5 and earlier allows
    attackers to connect to an attacker-specified URL using attacker-specified bearer token authentication.
    (CVE-2023-30525)

  - A missing permission check in Jenkins Report Portal Plugin 0.5 and earlier allows attackers with
    Overall/Read permission to connect to an attacker-specified URL using attacker-specified bearer token
    authentication. (CVE-2023-30526)

  - Jenkins WSO2 Oauth Plugin 1.0 and earlier stores the WSO2 Oauth client secret unencrypted in the global
    config.xml file on the Jenkins controller where it can be viewed by users with access to the Jenkins
    controller file system. (CVE-2023-30527)

  - Jenkins WSO2 Oauth Plugin 1.0 and earlier does not mask the WSO2 Oauth client secret on the global
    configuration form, increasing the potential for attackers to observe and capture it. (CVE-2023-30528)

  - Jenkins Lucene-Search Plugin 387.v938a_ecb_f7fe9 and earlier does not require POST requests for an HTTP
    endpoint, allowing attackers to reindex the database. (CVE-2023-30529)

  - Jenkins Consul KV Builder Plugin 2.0.13 and earlier stores the HashiCorp Consul ACL Token unencrypted in
    its global configuration file on the Jenkins controller where it can be viewed by users with access to the
    Jenkins controller file system. (CVE-2023-30530)

  - Jenkins Consul KV Builder Plugin 2.0.13 and earlier does not mask the HashiCorp Consul ACL Token on the
    global configuration form, increasing the potential for attackers to observe and capture it.
    (CVE-2023-30531)

  - A missing permission check in Jenkins TurboScript Plugin 1.3 and earlier allows attackers with Item/Read
    permission to trigger builds of jobs corresponding to the attacker-specified repository. (CVE-2023-30532)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.cloudbees.com/security-advisories/cloudbees-security-advisory-2023-04-12
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?92049620");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins Enterprise or Jenkins Operations Center to version 2.346.40.0.15 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-30520");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::combined_get_app_info(app:'Jenkins');

var constraints = [
  {
    'min_version' : '2.346',
    'fixed_version' :'2.346.40.0.15',
    'edition' : make_list('Enterprise', 'Operations Center')
  }
];

vcf::jenkins::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xsrf':TRUE, 'xss':TRUE}
);
