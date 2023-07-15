#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100844);
  script_version("1.5");
  script_cvs_date("Date: 2018/08/08 12:52:13");

  script_bugtraq_id(98989);

  script_name(english:"Splunk Enterprise < 5.0.19 / 6.0.15 / 6.1.14 / 6.2.14 / 6.3.11 Error Message Spoofing");
  script_summary(english:"Checks the version of Splunk Enterprise.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by an
error message spoofing vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Splunk
Enterprise running on the remote web server is 5.0.x prior to 5.0.19,
6.0.x prior to 6.0.15, 6.1.x prior to 6.1.14, 6.2.x prior to 6.2.14,
or 6.3.x prior to 6.3.11. It is, therefore, affected by an error
message spoofing vulnerability. An unauthenticated, remote attacker
can exploit this, by convincing a user to visit a specially crafted
website, to spoof the contents of error messages.");
  script_set_attribute(attribute:"see_also", value:"https://www.splunk.com/view/SP-CAAAP2U");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Splunk Enterprise version 5.0.19 / 6.0.15 / 6.1.14 / 6.2.14
/ 6.3.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("splunkd_detect.nasl", "splunk_web_detect.nasl");
  script_require_ports("Services/www", 8089, 8000);
  script_require_keys("installed_sw/Splunk");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Splunk";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8000, embedded:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
ver = install['version'];
license = install['License'];
if (isnull(license)) exit(1, "Unable to retrieve the Splunk license type.");

fix = FALSE;

install_url = build_url(qs:dir, port:port);

if (license == "Enterprise")
{
  # 5.0.x < 5.0.19
  if (ver =~ "^5\.0($|[^0-9])")
    fix = '5.0.19';

  # 6.0.x < 6.0.15
  else if (ver =~ "^6\.0($|[^0-9])")
    fix = '6.0.15';

  # 6.1.x < 6.1.14
  else if (ver =~ "^6\.1($|[^0-9])")
    fix = '6.1.14';

  # 6.2.x < 6.2.14
  else if (ver =~ "^6\.2($|[^0-9])")
    fix = '6.2.14';

  # 6.3.x < 6.3.11
  else if (ver =~ "^6\.3($|[^0-9])")
    fix = '6.3.11';
}

if (fix && ver_compare(ver:ver,fix:fix,strict:FALSE) < 0)
{
  order = make_list("URL", "Installed version", "Fixed version");
  report = make_array(
    order[0], install_url,
    order[1], ver + " " + license,
    order[2], fix + " " + license
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, ver + " " + license);
