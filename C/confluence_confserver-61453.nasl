#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149439);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-29445");
  script_xref(name:"IAVA", value:"2021-A-0240-S");

  script_name(english:"Atlassian Confluence < 7.11.0 SSRF (CONFSERVER-61453)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by a server-side request forgery vulnerability");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Atlassian Confluence application running on the remote host is 
prior to 7.11.0 . It is, therefore, affected by a server-side request forgery (SSRF) vulnerability in its Team Calendar
REST API component. An authenticated, remote attacker can exploit this, by sending crafted requests, to identify
internal hosts and ports.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONFSERVER-61453");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 7.11.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-29445");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("confluence_detect.nasl");
  script_require_keys("installed_sw/confluence");
  script_require_ports("Services/www", 8080, 8090);

  exit(0);
}

include('http.inc');
include('vcf.inc');

var port = get_http_port(default:80);
var app_info = vcf::get_app_info(app:'confluence', port:port, webapp:TRUE);
var ver = app_info['version'];

var constraints;

if (ver =~ "^7\.4")
  constraints = [{'min_version' : '7.4.0', 'fixed_version' : '7.4.8', 'fixed_display': '7.4.8 (LTS) / 7.11.0'}];

else
  constraints = [{'fixed_version' : '7.11', 'fixed_display': '7.11.0'}];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING
);
