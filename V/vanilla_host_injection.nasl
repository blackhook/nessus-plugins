#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(104659);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2016-10073");
  script_xref(name:"EDB-ID", value:"41996");

  script_name(english:"Vanilla Forums Header Injection Remote Code Execution");
  script_summary(english:"Checks Vanilla version from its homepage");

  script_set_attribute(attribute:"synopsis", value:
"Vanilla Forums contains a flaw that may allow a remote attacker to 
  obtain sensitive information via password reset request.");
  script_set_attribute(attribute:"description", value:
"The from method in library/core/class.email.php in Vanilla Forums 
before 2.3.1 allows remote attackers to spoof the email domain in sent
 messages and potentially obtain sensitive information via a crafted 
 HTTP Host header, as demonstrated by a password reset request.");
  # https://exploitbox.io/vuln/Vanilla-Forums-Exploit-Host-Header-Injection-CVE-2016-10073-0day.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fcce1c82");
  # https://legalhackers.com/advisories/Vanilla-Forums-Exploit-Host-Header-Injection-CVE-2016-10073-0day.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?879a187f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Vanilla 2.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-10073");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vanilla_forums_detect.nbin");
  script_require_keys("installed_sw/Vanilla Forums");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http.inc");
include("vcf.inc");

appname = 'Vanilla Forums';

get_install_count(app_name:appname, exit_if_zero:TRUE);

port = get_http_port(default:80,php:TRUE);

app_info = vcf::get_app_info(app:appname, port:port, webapp:TRUE);

constraints = [
  { "min_version" : "1.0.0", "max_version" : "2.3.0", "fixed_version" : "2.3.1" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);