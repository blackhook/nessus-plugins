#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99707);
  script_version("1.8");
  script_cvs_date("Date: 2019/01/02 11:18:37");

  script_bugtraq_id(98989);

  script_name(english:"Splunk Enterprise 6.4.x < 6.4.7 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Splunk Enterprise.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Splunk
Enterprise running on the remote web server is 6.4.x prior to 6.4.7.
It is, therefore, affected by multiple vulnerabilities :

  - Multiple cross-site scripting (XSS) vulnerabilities
    exist due to improper validation of user-supplied input.
    An unauthenticated, remote attacker can exploit these
    vulnerabilities, via a specially crafted request, to
    execute arbitrary script code in a user's browser
    session.
    
  - An error message spoofing vulnerability exists that
    allows an unauthenticated, remote attacker to spoof the
    contents of error messages by convincing a user to visit
    a specially crafted website.");
  script_set_attribute(attribute:"see_also", value:"https://www.splunk.com/view/SP-CAAAP2K");
  script_set_attribute(attribute:"see_also", value:"https://www.splunk.com/view/SP-CAAAP2U");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Splunk Enterprise version 6.4.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  # 6.4.x < 6.4.7
  if (ver =~ "^6\.4($|[^0-9])")
    fix = '6.4.7';
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

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING, xss:TRUE);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, ver + " " + license);

