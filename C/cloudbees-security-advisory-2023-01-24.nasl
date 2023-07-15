#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170555);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/03");

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

  script_name(english:"Jenkins Enterprise and Operations Center 2.346.x < 2.346.40.0.7 Multiple Vulnerabilities (CloudBees Security Advisory 2023-01-24)");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins Enterprise or Jenkins Operations Center running on the remote web server is 2.346.x prior to
2.346.40.0.7. It is, therefore, affected by multiple vulnerabilities including the following:

  - Sandbox bypass vulnerability in Script Security Plugin (CVE-2023-24422)

  - CSRF vulnerability in Gerrit Trigger Plugin (CVE-2023-24423)

  - Session fixation vulnerability in OpenId Connect Authentication Plugin (CVE-2023-24424)

  - Exposure of system-scoped Kubernetes credentials in Kubernetes Credentials Provider Plugin
    (CVE-2023-24425)

  - Session fixation vulnerability in Azure AD Plugin (CVE-2023-24426)

  - Session fixation vulnerability in Bitbucket OAuth Plugin (CVE-2023-24427)

  - CSRF vulnerability in Bitbucket OAuth Plugin (CVE-2023-24428)

  - Agent-to-controller security bypass in Semantic Versioning Plugin (CVE-2023-24429)

  - XXE vulnerability on agents in Semantic Versioning Plugin (CVE-2023-24430)

  - Missing permission checks in Orka by MacStadium Plugin allow enumerating credentials IDs (CVE-2023-24431)

  - CSRF vulnerability and missing permission checks in Orka by MacStadium Plugin allow capturing credentials
    (CVE-2023-24432, CVE-2023-24433)

  - CSRF vulnerability and missing permission checks in GitHub Pull Request Builder Plugin (CVE-2023-24434,
    CVE-2023-24435)

  - Missing permission check in GitHub Pull Request Builder Plugin allows enumerating credentials IDs
    (CVE-2023-24436)

  - CSRF vulnerability and missing permission checks in JIRA Pipeline Steps Plugin (CVE-2023-24437,
    CVE-2023-24438)

  - Keys stored in plain text by JIRA Pipeline Steps Plugin (CVE-2023-24439, CVE-2023-24440)

  - XXE vulnerability on agents in MSTest Plugin (CVE-2023-24441)

  - Credentials stored in plain text by GitHub Pull Request Coverage Status Plugin (CVE-2023-24442)

  - XXE vulnerability in TestComplete support Plugin (CVE-2023-24443)

  - Session fixation vulnerability in OpenID Plugin (CVE-2023-24444)

  - Open redirect vulnerability in OpenID Plugin (CVE-2023-24445)

  - CSRF vulnerability in OpenID Plugin (CVE-2023-24446)

  - CSRF vulnerability and missing permission check in RabbitMQ Consumer Plugin (CVE-2023-24447,
    CVE-2023-24448)

  - Path traversal vulnerability in PWauth Security Realm Plugin (CVE-2023-24449)

  - Passwords stored in plain text by view-cloner Plugin (CVE-2023-24450)

  - Missing permission checks in Cisco Spark Notifier Plugin allow enumerating credentials IDs
    (CVE-2023-24451)

  - CSRF vulnerability and missing permission check in TestQuality Updater Plugin (CVE-2023-24452,
    CVE-2023-24453)

  - Password stored in plain text by TestQuality Updater Plugin (CVE-2023-24454)

  - Path traversal vulnerability in visualexpert Plugin (CVE-2023-24455)

  - Session fixation vulnerability in Keycloak Authentication Plugin (CVE-2023-24456)

  - CSRF vulnerability in Keycloak Authentication Plugin (CVE-2023-24457)

  - CSRF vulnerability and missing permission check in BearyChat Plugin (CVE-2023-24458, CVE-2023-24459)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.cloudbees.com/security-advisories/cloudbees-security-advisory-2023-01-24
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01c53c96");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins Enterprise or Jenkins Operations Center to version 2.346.40.0.7 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24458");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-24456");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/24");

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
    'fixed_version' :'2.346.40.0.7',
    'edition' : make_list('Enterprise', 'Operations Center')
  }
];

vcf::jenkins::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xsrf':TRUE}
);
