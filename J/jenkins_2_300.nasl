#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151193);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2021-21670",
    "CVE-2021-21671",
    "CVE-2021-21672",
    "CVE-2021-21673",
    "CVE-2021-21674"
  );
  script_xref(name:"IAVA", value:"2021-A-0335-S");

  script_name(english:"Jenkins LTS < 2.289.2 / Jenkins weekly < 2.300 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its its self-reported version number, the version of Jenkins running on the remote web server is Jenkins
LTS prior to 2.289.2 or Jenkins weekly prior to 2.300. It is, therefore, affected by multiple vulnerabilities:

  - Jenkins 2.299 and earlier, LTS 2.289.1 and earlier allows users to cancel queue items and abort builds of
    jobs for which they have Item/Cancel permission even when they do not have Item/Read permission. Jenkins
    2.300, LTS 2.289.2 requires that users have Item/Read permission for applicable types in addition to
    Item/Cancel permission. As a workaround on earlier versions of Jenkins, do not grant Item/Cancel
    permission to users who do not have Item/Read permission. (CVE-2021-21670)

  - Jenkins 2.299 and earlier, LTS 2.289.1 and earlier does not invalidate the existing session on login. This
    allows attackers to use social engineering techniques to gain administrator access to Jenkins. This
    vulnerability was introduced in Jenkins 2.266 and LTS 2.277.1. Jenkins 2.300, LTS 2.289.2 invalidates the
    existing session on login. Note In case of problems, administrators can choose a different implementation
    by setting the Java system property hudson.security.SecurityRealm.sessionFixationProtectionMode to 2, or
    disable the fix entirely by setting that system property to 0. (CVE-2021-21671)

  - Selenium HTML report Plugin 1.0 and earlier does not configure its XML parser to prevent XML external
    entity (XXE) attacks. This allows attackers with the ability to control the report files parsed using this
    plugin to have Jenkins parse a crafted report file that uses external entities for extraction of secrets
    from the Jenkins controller or server-side request forgery. Selenium HTML report Plugin 1.1 disables
    external entity resolution for its XML parser. (CVE-2021-21672)

  - CAS Plugin 1.6.0 and earlier improperly determines that a redirect URL after login is legitimately
    pointing to Jenkins. This allows attackers to perform phishing attacks by having users go to a Jenkins URL
    that will forward them to a different site after successful authentication. CAS Plugin 1.6.1 only
    redirects to relative (Jenkins) URLs. (CVE-2021-21673)

  - requests-plugin Plugin 2.2.6 and earlier does not perform a permission check in an HTTP endpoint. This
    allows attackers with Overall/Read permission to view the list of pending requests. requests-plugin Plugin
    2.2.7 requires Overall/Read permission to view the list of pending requests. (CVE-2021-21674)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2021-06-30");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins weekly to version 2.300 or later or Jenkins LTS to version 2.289.2 or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21673");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-21671");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::combined_get_app_info(app:'Jenkins');

var constraints = [
  { 'max_version' : '2.299',    'fixed_version' : '2.300',    'edition' : 'Open Source' },
  { 'max_version' : '2.289.1',  'fixed_version' : '2.289.2',  'edition' : 'Open Source LTS' }
];

vcf::jenkins::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
