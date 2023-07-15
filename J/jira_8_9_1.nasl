#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(138838);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-4022", "CVE-2020-4024", "CVE-2020-4025");
  script_xref(name:"IAVA", value:"2020-A-0284-S");

  script_name(english:"Atlassian Jira < 8.5.5 / 8.6.x < 8.8.2 / 8.9.x < 8.9.1 Multiple Cross-Site Scripting (XSS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by a Multiple Cross-Site Scripting (XSS) vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Atlassian Jira hosted on the remote web server is
prior to 8.5.5, or version 8.6.x prior to 8.8.2, 8.9.x prior to 8.9.1. It is, therefore, affected by a multiple
Cross-Site scripting (XSS) vulnerabilities.

  - Remote attackers can inject arbitrary HTML or JavaScript in issue attachments. (CVE-2020-4022)
  - Remote attackers can inject arbitrary HTML or JavaScript in issue attachments with a vnd.wap.xhtml+xml
    content type. (CVE-2020-4024)
  - Remote attackers can inject arbitrary HTML or JavaScript in issue attachments with a rdf content type.
    (CVE-2020-4025)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-71107");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-71113");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-71114");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Jira version 8.5.5, 8.8.2, 8.9.1, 8.10.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4022");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jira_detect.nasl", "atlassian_jira_win_installed.nbin", "atlassian_jira_nix_installed.nbin");
  script_require_keys("installed_sw/Atlassian JIRA");

  exit(0);
}

include('vcf.inc');

app_info = vcf::combined_get_app_info(app:'Atlassian JIRA');

constraints = [
  { 'fixed_version' : '8.5.5' },
  { 'min_version' : '8.6.0', 'fixed_version' : '8.8.2' },
  { 'min_version' : '8.9.0', 'fixed_version' : '8.9.1',   'fixed_display' : '8.9.1 / 8.10.0' }
];
vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{xss:TRUE}
);