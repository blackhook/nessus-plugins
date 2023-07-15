#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104850);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2017-17067");
  script_xref(name:"IAVB", value:"2017-B-0163-S");

  script_name(english:"Splunk Enterprise 6.3.x < 6.3.12 / 6.4.x < 6.4.9 / 6.5.x < 6.5.6 / 6.6 < 6.6.3.2 or 6.6.4 / 7.0.x < 7.0.0.1 Multiple SAML Implementation Vulnerabilities");
  script_summary(english:"Checks the version of Splunk Enterprise.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by
multiple SAML implementation vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Splunk
running on the remote web server is 6.3.x prior to 6.3.12, 6.4.x prior
to 6.4.9, 6.5.x prior to 6.5.6, 6.6.x prior to 6.6.3.2 or 6.6.4, or
7.0.x prior to 7.0.0.1. It is, therefore, affected by multiple SAML
implementation vulnerabilities.

Note that this only affects Splunk Enterprise components running
Splunk Web with SAML authentication enabled.");
  script_set_attribute(attribute:"see_also", value:"https://www.splunk.com/view/SP-CAAAP3K");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Splunk Enterprise version 6.3.12 / 6.4.9 / 6.5.6 / 6.6.3.2
/ 6.6.4 / 7.0.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2022 Tenable Network Security, Inc.");

  script_dependencies("splunkd_detect.nasl", "splunk_web_detect.nasl");
  script_require_ports("Services/www", 8089, 8000);
  script_require_keys("installed_sw/Splunk", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

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
  if (ver =~ "^6\.3($|[^0-9])")
    fix = '6.3.12';
  else if (ver =~ "^6\.4($|[^0-9])")
    fix = '6.4.9';
  else if (ver =~ "^6\.5($|[^0-9])")
    fix = '6.5.6';
  else if (ver =~ "^6\.6($|[^0-9])")
    fix = '6.6.3.2';
  else if (ver =~ "^7\.0($|[^0-9])")
    fix = '7.0.0.1';
}

if (fix && ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  if (fix == '6.6.3.2')
    fix = '6.6.3.2 or 6.6.4';

  order = make_list("URL", "Installed version", "Fixed version");
  report = make_array(
    order[0], install_url,
    order[1], ver + " " + license,
    order[2], fix + " " + license
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, ver + " " + license);
