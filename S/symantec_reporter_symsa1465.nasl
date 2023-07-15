#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121254);
  script_version("1.5");
  script_cvs_date("Date: 2019/10/31 15:18:51");

  script_cve_id("CVE-2018-12237");
  script_bugtraq_id(106518);

  script_name(english:"Symantec (Blue Coat) Reporter CLI OS Command Injection Vulnerability (SYMSA1465)");
  script_summary(english:"Checks the version of Symantec Reporter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a version of Symantec (Blue Coat)
Reporter CLI that is affected by an OS command injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Symantec
(formerly Blue Coat) Reporter installation running on the remote
host is 10.1 prior to 10.1.5.6 or 10.2 prior to 10.2.1.8. It is, 
therefore, affected by an OS command injection vulnerability. An
authenticated attacker with Enable mode administrator access can
execute arbitrary OS commands with elevated system privileges.

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version
number.");
  # https://support.symantec.com/en_US/article.SYMSA1465.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab29c0bf");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Reporter version 10.1.5.6 / 10.2.1.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12237");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:reporter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("symantec_reporter_web_detection.nbin");
  script_require_keys("installed_sw/Symantec Reporter");
  script_require_ports("Services/www");

  exit(0);
}

include("http.inc");
include("vcf.inc");

port = get_http_port(default:8082);

app = "Symantec Reporter";

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:4);

constraints = [
  { "min_version" : "10.1.0.0", "max_version" : "10.1.5.5", "fixed_version" : "10.1.5.6" },
  { "min_version" : "10.2.0.0", "max_version" : "10.2.1.7", "fixed_version" : "10.2.1.8" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
