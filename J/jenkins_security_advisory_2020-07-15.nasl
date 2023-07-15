#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(138887);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2020-2220",
    "CVE-2020-2221",
    "CVE-2020-2222",
    "CVE-2020-2223"
  );
  script_xref(name:"IAVA", value:"2020-A-0337-S");

  script_name(english:"Jenkins ( < 2.235.2 LTS / < 2.245 Weekly) Multiple Stored XSS (Jenkins Security Advisory 2020-07-15)");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple stored XSS 
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins running on the remote web server is prior to 2.245 or is a version of Jenkins LTS prior to 
2.235.2. It is, therefore, affected by multiple stored cross-site scripting (XSS) vulnerabilities in various components 
including its build time trend page, build cause page, tooltips & build console page. This is due to improper 
validation of user-supplied input before returning it to users. An authenticated, remote attacker can exploit this, by 
convincing a user to click a specially crafted URL, to execute arbitrary script code in a user's browser session.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.jenkins.io/security/advisory/2020-07-15/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1846d83d");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins weekly to version 2.245 or later. Upgrade Jenkins LTS to version 2.235.2 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2220");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::combined_get_app_info(app:'Jenkins');

var constraints = [
  { 'fixed_version' : '2.245',    'fixed_display' : '2.235.2 LTS / 2.245',  'edition' : 'Open Source' },
  { 'fixed_version' : '2.235.2',  'fixed_display' : '2.235.2 LTS / 2.245',  'edition' : 'Open Source LTS' }
];

vcf::jenkins::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE,
  flags:{'xss':TRUE}
);
