#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128417);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/17 14:31:04");

  script_cve_id("CVE-2019-12753");
  script_bugtraq_id(109829);
  script_xref(name:"IAVA", value:"2019-A-0310");

  script_name(english:"Symantec (Blue Coat) Reporter UI Information Disclosure Vulnerability (SYMSA1489)");
  script_summary(english:"Checks the version of Symantec Reporter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a version of Symantec Reporter (Blue Coat) 
 that is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Symantec
(formerly Blue Coat) Reporter installation running on the remote
host is 10.3 prior to 10.3.2.5. It is, therefore, affected by an 
information disclosure vulnerability. An authenticated attacker 
with Reporter UI access can obtain passwords for 
external servers that they might not be authorized to access.

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version
number.");
  # https://support.symantec.com/us/en/article.SYMSA1489.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7bf6aa9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Reporter version 10.3.2.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12753");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:reporter");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("symantec_reporter_web_detection.nbin");
  script_require_keys("installed_sw/Symantec Reporter");
  script_require_ports("Services/www");

  exit(0);
}

include('http.inc');
include('vcf.inc');

port = get_http_port(default:8082);

app = 'Symantec Reporter';

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:4);

constraints = [
  { "min_version" : "10.3.0.0", "fixed_version" : "10.3.2.5" },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
