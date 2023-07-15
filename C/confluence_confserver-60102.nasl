#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(139205);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-14175");
  script_xref(name:"IAVA", value:"2020-A-0341-S");

  script_name(english:"Atlassian Confluence < 7.4.2 / 7.5.x < 7.5.2 XSS (CONFSERVER-60102)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by a cross-site scripting (XSS) vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Atlassian Confluence application running on the remote host is prior
to 7.4.2 or 7.5.x prior to 7.5.2. It is, therefore, affected by a cross-site scripting (XSS) vulnerability in user macro
parameters. An authenticated, remote attacker can exploit this to inject HTML and JavaScript to execute arbitrary script
code in a user's browser session.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONFSERVER-60102");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 7.4.2, 7.5.2, 7.6.0, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14175");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("confluence_detect.nasl");
  script_require_keys("installed_sw/confluence");
  script_require_ports("Services/www", 8080, 8090);

  exit(0);
}

include('vcf.inc');
include('http.inc');

app_name = 'confluence';

port = get_http_port(default:80);

app_info = vcf::get_app_info(app:app_name, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'fixed_version': '7.4.2' },
  { 'min_version': '7.5.0',  'fixed_version': '7.5.2', 'fixed_display': '7.5.2 / 7.6.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE, flags:{xss:TRUE});
