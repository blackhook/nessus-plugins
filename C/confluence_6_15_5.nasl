#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(136178);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-20102");
  script_xref(name:"IAVA", value:"2020-A-0183-S");

  script_name(english:"Atlassian Confluence 6.14.x < 6.14.3 / 6.15.x < 6.15.5 stored cross-site-scripting (SXSS) Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by a local file disclosure vulnerability");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Atlassian Confluence 
application running on the remote host is 6.14.x prior to 6.14.3, 
or 6.15.x prior to 6.15.5. It is, therefore, affected by a stored 
cross-site-scripting (SXSS) vulnerability. due to improper validation
of user-supplied input before returning it to users. An unauthenticated, 
remote attacker can exploit this, via a malicious attachment with a modified
`mimeType` parameter, to execute arbitrary script code in a user's browser 
session.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://nvd.nist.gov/vuln/detail/CVE-2019-20102");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 6.14.3, 6.15.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-20102");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

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

app_info = vcf::get_app_info(app:app_name, port:port, webapp:true);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  {"min_version": "6.14.0",  "fixed_version": "6.14.3", "fixed_display": "6.14.3" },
  {"min_version": "6.15.0",  "fixed_version": "6.15.5", "fixed_display": "6.15.5" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{'xss':TRUE});
