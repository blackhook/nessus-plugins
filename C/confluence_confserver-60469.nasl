#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(146869);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-29448");
  script_xref(name:"IAVA", value:"2021-A-0105-S");

  script_name(english:"Atlassian Confluence < 6.13.18 / 6.14 < 7.4.6 / 7.5 < 7.8.3 Arbitrary File Read (CONFSERVER-60469)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by an arbitrary file read vulnerability");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Atlassian Confluence application running on the remote host is 
prior to 6.13.18, 6.14.x prior to 7.4.6 or 7.5.x prior to 7.8.3. It is, therefore, affected by an arbitrary file
read vulnerability in its ConfluenceResourceDownloadRewriteRule class due to an incorrect path access check. An 
unauthenticated, remote attacker can exploit this to read arbitrary files within WEB-INF and META-INF.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONFSERVER-60469");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 6.13.18, 7.4.6, 7.8.3, 7.9.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-29448");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/26");

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

port = get_http_port(default:80);
app_info = vcf::get_app_info(app:'confluence', port:port, webapp:true);

constraints = [
  {'fixed_version' : '6.13.18' },
  {'min_version' : '6.14', 'fixed_version' : '7.4.6' },
  {'min_version' : '7.5', 'fixed_version' : '7.8.3', 'fixed_display' : '7.8.3 / 7.9.0'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
