#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169509);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/07");

  script_cve_id("CVE-2022-26134");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/06");
  script_xref(name:"CEA-ID", value:"CEA-2022-0023");

  script_name(english:"Atlassian Confluence Command Injection (CONFSERVER-79016)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by a command injection
vulnerability");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Atlassian Confluence running
on the remote host is affected by a command injection vulnerability. A remote,
unauthenticated attacker can use this to execute arbitrary code.

Note that Nessus has not tested for this issue but has instead relied only on
the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONFSERVER-79016");
  # https://confluence.atlassian.com/doc/confluence-security-advisory-2022-06-02-1130377146.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c1df4fa0");
  # https://www.volexity.com/blog/2022/06/02/zero-day-exploitation-of-atlassian-confluence/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5cd914cb");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 7.4.17, 7.13.7, 7.14.3, 7.15.2, 7.16.4, 7.17.4, 7.18.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26134");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Atlassian Confluence Namespace OGNL Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("confluence_win_installed.nbin", "confluence_nix_installed.nbin", "confluence_detect.nasl");
  script_require_keys("installed_sw/Atlassian Confluence");

  exit(0);
}

include('vcf.inc');

var app_name = 'Atlassian Confluence';

var app_info = vcf::combined_get_app_info(app:app_name);
vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  {"min_version": "1.3.0",  "fixed_version": "7.4.17",  "fixed_display": "7.4.17 / 7.18.1"},
  {"min_version": "7.5.0",  "fixed_version": "7.13.7",  "fixed_display": "7.13.7 / 7.18.1"},
  {"min_version": "7.14.0", "fixed_version": "7.14.3",  "fixed_display": "7.14.3 / 7.18.1"},
  {"min_version": "7.15.0", "fixed_version": "7.15.2",  "fixed_display": "7.15.2 / 7.18.1"},
  {"min_version": "7.16.0", "fixed_version": "7.16.4",  "fixed_display": "7.16.4 / 7.18.1"},
  {"min_version": "7.17.0", "fixed_version": "7.17.4",  "fixed_display": "7.17.4 / 7.18.1"},
  {"min_version": "7.18.0", "fixed_version": "7.18.1",  "fixed_display": "7.18.1"}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
