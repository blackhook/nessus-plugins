#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124330);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-20237");
  script_bugtraq_id(107041);
  script_xref(name:"IAVA", value:"2019-A-0135-S");

  script_name(english:"Atlassian Confluence < 6.13.1 Information Disclosure Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by an information disclosure vulnerability");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Atlassian
Confluence application running on the remote host is prior to 6.13.1.
It is therefore, affected by an information disclosure vulnerability
which exists in the 'Word Export' component. An authenticated, remote
attacker can exploit this which may lead to recovery of already
deleted content pages.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONFSERVER-57814");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 6.13.1, 6.14.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-20237");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("confluence_detect.nasl");
  script_require_keys("installed_sw/confluence", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8080, 8090);

  exit(0);
}

include("vcf.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = "confluence";

port = get_http_port(default:80);

app_info = vcf::get_app_info(app:app_name, port:port, webapp:true);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  # <= 6.12.0
  { "max_version": "6.12.0", "fixed_display": "6.13.1 / 6.14.0" },
  # 6.13.x < 6.13.1
  { "min_version": "6.13.0", "fixed_version": "6.13.1", "fixed_display": "6.13.1 / 6.14.0" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
