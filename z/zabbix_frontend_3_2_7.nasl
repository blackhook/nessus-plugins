#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102495);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Zabbix 3.2.x < 3.2.7 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Zabbix
running on the remote host is 3.2.x prior to 3.2.7. It is,
therefore, affected by multiple vulnerabilities :

  - A flaw exists that allows a reflected cross-site scripting (XSS)
    attack. This flaw exists because the actionconf.php script does
    not validate input to the 'tab' parameter before returning it
    to users. This may allow a context-dependent attacker to create
    a specially crafted request that will execute arbitrary script
    code in a user's browser session within the trust relationship
    between their browser and the server.

  - An unspecified flaw exists that may allow a remote attacker to
    execute arbitrary commands on the server.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.zabbix.com/rn/rn3.2.7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zabbix version 3.2.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zabbix:zabbix");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("zabbix_frontend_detect.nasl");
  script_require_keys("installed_sw/zabbix");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("vcf.inc");
include("http.inc");

app = "zabbix";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
      { "min_version" : "3.2.0", "fixed_version" : "3.2.7" }

];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{xss:TRUE});

