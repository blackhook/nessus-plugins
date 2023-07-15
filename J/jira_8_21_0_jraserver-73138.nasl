#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159092);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2021-43952");
  script_xref(name:"IAVA", value:"2022-A-0117");

  script_name(english:"Atlassian Jira < 8.13.18 / 8.14.x < 8.20.6 / 8.21.0 XSRF (JRASERVER-73138)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by a cross-site request forgery vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Atlassian Jira hosted on the remote web server is
affected by a cross-site request forgery (XSRF) vulnerability. Affected versions of Atlassian Jira Server and Data
Center allow unauthenticated remote attackers to restore the default configuration of fields via a Cross-Site Request
Forgery vulnerability in the /secure/admin/RestoreDefaults.jspa endpoint. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-73138");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Jira version 8.13.18, 8.20.6, 8.21.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43952");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jira_detect.nasl", "atlassian_jira_win_installed.nbin", "atlassian_jira_nix_installed.nbin");
  script_require_keys("installed_sw/Atlassian JIRA");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Atlassian JIRA');

var constraints = [
  {'fixed_version': '8.13.18'},
  {'min_version' : '8.14', 'fixed_version': '8.20.6', 'fixed_display' : '8.20.6 / 8.21.0'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xsrf':TRUE}
);
