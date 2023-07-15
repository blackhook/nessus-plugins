#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104655);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Zabbix 3.0.x < 3.0.13 / 3.2.x < 3.2.10 / 3.4.x < 3.4.4 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Zabbix
running on the remote host is 3.0.x prior to 3.0.13, 3.2.x prior to
3.2.10, or 3.4.x prior to 3.4.4. It is, therefore, affected by
multiple unspecified vulnerabilities.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.zabbix.com/rn/rn3.0.13");
  script_set_attribute(attribute:"see_also", value:"https://www.zabbix.com/rn/rn3.2.10");
  script_set_attribute(attribute:"see_also", value:"https://www.zabbix.com/rn/rn3.4.4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zabbix version 3.0.13 / 3.2.10 / 3.4.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zabbix:zabbix");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2022 Tenable Network Security, Inc.");

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
      { "min_version" : "3.0.0", "fixed_version" : "3.0.13" },
      { "min_version" : "3.2.0", "fixed_version" : "3.2.10" },
      { "min_version" : "3.4.0", "fixed_version" : "3.4.4" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
