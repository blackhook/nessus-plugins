#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106399);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2017-15531");
  script_bugtraq_id(102751);

  script_name(english:"Symantec (Blue Coat) Reporter Multiple Vulnerabilities (SA158)");
  script_summary(english:"Checks the version of Symantec Reporter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a version of Symantec (Blue Coat) Reporter that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Symantec (formerly Blue Coat) Reporter
installation running on the remote host is 9.5 prior to 9.5.4.1. It is, therefore, affected
by multiple vulnerabilities.

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  # https://www.symantec.com/security-center/network-protection-security-advisories/SA158
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f6a711b3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Reporter version 9.5.4.1 / 10.2.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15531");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bluecoat:reporter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bluecoat_reporter.nasl");
  script_require_keys("installed_sw/BlueCoat Reporter");
  script_require_ports("Services/www");

  exit(0);
}

include("http.inc");
include("vcf.inc");

port = get_http_port(default:8082);

app = "BlueCoat Reporter";

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:4);

constraints = [
  { "min_version" : "9.5.0.0", "max_version" : "9.5.4.0", "fixed_version" : "9.5.4.1" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
