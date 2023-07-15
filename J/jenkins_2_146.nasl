#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118147);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2018-1000406",
    "CVE-2018-1000407",
    "CVE-2018-1000408",
    "CVE-2018-1000409",
    "CVE-2018-1000410",
    "CVE-2018-1000997",
    "CVE-2018-1999043"
  );
  script_bugtraq_id(106532);
  script_xref(name:"TRA", value:"TRA-2018-29");

  script_name(english:"Jenkins < 2.138.2 (LTS) / 2.146 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins running on the remote web server is prior to 2.146 or is a version of Jenkins LTS prior to 
2.138.2. It is, therefore, affected by multiple vulnerabilities:
  - A cross-site scripting (XSS) vulnerability exists due to improper validation of user-supplied input before 
    returning it to users. An unauthenticated, remote attacker can exploit this, by convincing a user to click a 
    specially crafted URL, to execute arbitrary script code in a user's browser session (CVE-2018-1000407).

  - A denial of service (DoS) vulnerability exists in the HudsonPrivateSecurityRealm class of Jenkins. An 
    unauthenticated, remote attacker can exploit this issue, by sending crafted, repeated HTTP requests to particular 
    URLs, to cause the application to stop responding (CVE-2018-1000408).

  - A directory traversal vulnerability exists in the version of the Stapler Web Framework, which is bundled with 
    Jenkins. An authenticated, remote attacker can exploit this, by sending a URI that contains directory traversal 
    characters, to disclose the contents of files located outside of the server's restricted path (CVE-2018-1000997).

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2018-10-10/");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2018-29");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins to version 2.146 or later, Jenkins LTS to version 
2.138.2 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1000408");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::combined_get_app_info(app:'Jenkins');

var constraints = [
  { 'fixed_version' : '2.146',    'edition' : 'Open Source' },
  { 'fixed_version' : '2.138.2',  'edition' : 'Open Source LTS' }
];

vcf::jenkins::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
