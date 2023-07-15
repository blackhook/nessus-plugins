#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173193);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/10");

  script_cve_id(
    "CVE-2023-28668",
    "CVE-2023-28669",
    "CVE-2023-28670",
    "CVE-2023-28671",
    "CVE-2023-28672",
    "CVE-2023-28673",
    "CVE-2023-28674",
    "CVE-2023-28675",
    "CVE-2023-28676",
    "CVE-2023-28677",
    "CVE-2023-28678",
    "CVE-2023-28679",
    "CVE-2023-28680",
    "CVE-2023-28681",
    "CVE-2023-28682",
    "CVE-2023-28683",
    "CVE-2023-28684",
    "CVE-2023-28685"
  );

  script_name(english:"Jenkins Enterprise and Operations Center 2.346.x < 2.346.40.0.12 Multiple Vulnerabilities (CloudBees Security Advisory 2023-03-21-security-advisory)");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins Enterprise or Jenkins Operations Center running on the remote web server is 2.346.x prior to
2.346.40.0.12. It is, therefore, affected by multiple vulnerabilities including the following:

  - Medium Permissions in Jenkins can be enabled and disabled. Some permissions are disabled by default, e.g.,
    Overall/Manage or Item/Extended Read. Disabled permissions cannot be granted directly, only through
    greater permissions that imply them (e.g., Overall/Administer or Item/Configure). Role-based Authorization
    Strategy Plugin 587.v2872c41fa_e51 and earlier grants permissions even after they've been disabled. This
    allows attackers to have greater access than they're entitled to after the following operations took
    place: A permission is granted to attackers directly or through groups. The permission is disabled, e.g.,
    through the script console. Role-based Authorization Strategy Plugin 587.588.v850a_20a_30162 does not
    grant disabled permissions. (CVE-2023-28668)

  - High JaCoCo Plugin 3.3.2 and earlier does not escape class and method names shown on the UI. This results
    in a stored cross-site scripting (XSS) vulnerability exploitable by attackers able to control input files
    for the 'Record JaCoCo coverage report' post-build action. JaCoCo Plugin 3.3.2.1 escapes class and method
    names shown on the UI. (CVE-2023-28669)

  - High Pipeline Aggregator View Plugin 1.13 and earlier does not escape a variable representing the current
    view's URL in inline JavaScript. This results in a stored cross-site scripting (XSS) vulnerability
    exploitable by authenticated attackers with Overall/Read permission. Pipeline Aggregator View Plugin 1.14
    obtains the current URL in a way not susceptible to XSS. (CVE-2023-28670)

  - Medium OctoPerf Load Testing Plugin Plugin 4.5.0 and earlier does not require POST requests for a
    connection test HTTP endpoint, resulting in a cross-site request forgery (CSRF) vulnerability. This
    vulnerability allows attackers to connect to an attacker-specified URL using attacker-specified
    credentials IDs obtained through another method, capturing credentials stored in Jenkins. OctoPerf Load
    Testing Plugin Plugin 4.5.1 requires POST requests for the affected connection test HTTP endpoint.
    (CVE-2023-28671)

  - High OctoPerf Load Testing Plugin Plugin 4.5.1 and earlier does not perform a permission check in a
    connection test HTTP endpoint. This allows attackers with Overall/Read permission to connect to an
    attacker-specified URL using attacker-specified credentials IDs obtained through another method, capturing
    credentials stored in Jenkins. OctoPerf Load Testing Plugin Plugin 4.5.2 properly performs a permission
    check when accessing the affected connection test HTTP endpoint. (CVE-2023-28672)

  - Medium OctoPerf Load Testing Plugin Plugin 4.5.2 and earlier does not perform a permission check in an
    HTTP endpoint. This allows attackers with Overall/Read permission to enumerate credentials IDs of
    credentials stored in Jenkins. Those can be used as part of an attack to capture the credentials using
    another vulnerability. An enumeration of credentials IDs in OctoPerf Load Testing Plugin Plugin 4.5.3
    requires the appropriate permissions. (CVE-2023-28673)

  - Medium OctoPerf Load Testing Plugin Plugin 4.5.2 and earlier does not perform permission checks in several
    HTTP endpoints. This allows attackers with Overall/Read permission to connect to a previously configured
    Octoperf server using attacker-specified credentials. Additionally, these endpoints do not require POST
    requests, resulting in a cross-site request forgery (CSRF) vulnerability. OctoPerf Load Testing Plugin
    Plugin 4.5.3 requires POST requests and the appropriate permissions for the affected HTTP endpoints.
    (CVE-2023-28674, CVE-2023-28675)

  - High Convert To Pipeline Plugin 1.0 and earlier does not require POST requests for the HTTP endpoint
    converting a Freestyle project to Pipeline, resulting in a cross-site request forgery (CSRF)
    vulnerability. This vulnerability allows attackers to create a Pipeline based on a Freestyle project.
    Combined with SECURITY-2966, this can result in the execution of unsandboxed Pipeline scripts. As of
    publication of this advisory, there is no fix. Learn why we announce this. (CVE-2023-28676)

  - High Convert To Pipeline Plugin 1.0 and earlier uses basic string concatenation to convert Freestyle
    projects' Build Environment, Build Steps, and Post-build Actions to the equivalent Pipeline step
    invocations. This allows attackers able to configure Freestyle projects to prepare a crafted configuration
    that injects Pipeline script code into the (unsandboxed) Pipeline resulting from a conversion by Convert
    To Pipeline Plugin. If an administrator converts the Freestyle project to a Pipeline, the script will be
    pre-approved. As of publication of this advisory, there is no fix. Learn why we announce this.
    (CVE-2023-28677)

  - High Cppcheck Plugin 1.26 and earlier does not escape file names from Cppcheck report files before showing
    them on the Jenkins UI. This results in a stored cross-site scripting (XSS) vulnerability exploitable by
    attackers able to control report file contents. As of publication of this advisory, there is no fix. Learn
    why we announce this. (CVE-2023-28678)

  - High Mashup Portlets Plugin 1.1.2 and earlier provides the Generic JS Portlet feature that lets a user
    populate a portlet using a custom JavaScript expression. This results in a stored cross-site scripting
    (XSS) vulnerability exploitable by authenticated attackers with Overall/Read permission. As of publication
    of this advisory, there is no fix. Learn why we announce this. (CVE-2023-28679)

  - High Crap4J Plugin 0.9 and earlier does not configure its XML parser to prevent XML external entity (XXE)
    attacks. This allows attackers able to control Crap Report file contents to have Jenkins parse a crafted
    XML document that uses external entities for extraction of secrets from the Jenkins controller or server-
    side request forgery. As of publication of this advisory, there is no fix. Learn why we announce this.
    (CVE-2023-28680)

  - High Visual Studio Code Metrics Plugin 1.7 and earlier does not configure its XML parser to prevent XML
    external entity (XXE) attacks. This allows attackers able to control VS Code Metrics File contents to have
    Jenkins parse a crafted XML document that uses external entities for extraction of secrets from the
    Jenkins controller or server-side request forgery. As of publication of this advisory, there is no fix.
    Learn why we announce this. (CVE-2023-28681)

  - High Performance Publisher Plugin 8.09 and earlier does not configure its XML parser to prevent XML
    external entity (XXE) attacks. This allows attackers able to control PerfPublisher report files to have
    Jenkins parse a crafted XML document that uses external entities for extraction of secrets from the
    Jenkins controller or server-side request forgery. As of publication of this advisory, there is no fix.
    Learn why we announce this. (CVE-2023-28682)

  - High Phabricator Differential Plugin 2.1.5 and earlier does not configure its XML parser to prevent XML
    external entity (XXE) attacks. This allows attackers able to control coverage report file contents for the
    'Post to Phabricator' post-build action to have Jenkins parse a crafted XML document that uses external
    entities for extraction of secrets from the Jenkins controller or server-side request forgery. As of
    publication of this advisory, there is no fix. Learn why we announce this. (CVE-2023-28683)

  - High remote-jobs-view-plugin Plugin 0.0.3 and earlier does not configure its XML parser to prevent XML
    external entity (XXE) attacks. This allows authenticated attackers with Overall/Read permission to have
    Jenkins parse a crafted XML document that uses external entities for extraction of secrets from the
    Jenkins controller or server-side request forgery. As of publication of this advisory, there is no fix.
    Learn why we announce this. (CVE-2023-28684)

  - High AbsInt a Plugin 1.1.0 and earlier does not configure its XML parser to prevent XML external entity
    (XXE) attacks. This allows attackers able to control 'Project File (APX)' contents to have Jenkins parse a
    crafted XML document that uses external entities for extraction of secrets from the Jenkins controller or
    server-side request forgery. As of publication of this advisory, there is no fix. Learn why we announce
    this. (CVE-2023-28685)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.cloudbees.com/security-advisories/cloudbees-security-advisory-2023-03-21-security-advisory
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c72f3eb7");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins Enterprise or Jenkins Operations Center to version 2.346.40.0.12 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28677");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/21");

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
    'fixed_version' :'2.346.40.0.12',
    'edition' : make_list('Enterprise', 'Operations Center')
  }
];

vcf::jenkins::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xsrf':TRUE, 'xss':TRUE}
);
