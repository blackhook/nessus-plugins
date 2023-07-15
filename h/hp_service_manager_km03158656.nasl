#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109917);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-6494");
  script_xref(name:"IAVB", value:"2018-B-0063");

  script_name(english:"HP Service Manager 9.30.x / 9.31.x / 9.32.x / 9.33.x / 9.34.x / 9.35.x < 9.35.6007 / 9.40.x / 9.41.x < 9.41.6000 / 9.50.x / 9.51.x Remote SQL Injection");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by an SQL
injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The HP Service Manager application running on the remote host is
version 9.30.x; 9.31.x; 9.32.x; 9.33.x; 9.34.x; 9.35.x prior to
9.35.6007; 9.40.x; 9.41.x prior to 9.41.6000; 9.50.x; or 9.51.x. It
is, therefore, affected by an SQL injection vulnerability.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://softwaresupport.softwaregrp.com/document/-/facetsearch/document/KM03158656
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?46faa2bc");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP Service Manager version 9.35.6007 / 9.41.6000 /
9.52.2021 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6494");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:service_manager");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hp_service_manager_detect.nbin");
  script_require_keys("installed_sw/HP Service Manager");
  script_require_ports("Services/www", 443, 13080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app_name = "HP Service Manager";
get_install_count(app_name:app_name, exit_if_zero:TRUE);

port = get_http_port(default:13080);
install = get_single_install(app_name:app_name, port:port, exit_if_unknown_ver:TRUE);
version = install['version'];
url = build_url(port:port, qs:install['path']);

fix = NULL;
vuln = FALSE;

# 9.30.x, 9.31.x, 9.32.x, 9.33.x, 9.34.x, 9.35.x
if (version =~ "^9\.3[0-5](\.|$)")
{
  fix = "9.35.6007";
}
# 9.40.x, 9.41.x
else if (version =~ "^9\.4[0-1](\.|$)")
{
  fix = "9.41.6000";
}
# 9.50.x, 9.51.x
else if (version =~ "^9\.5[0-1](\.|$)")
{
  fix = "9.52.2021";
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url, version);

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  items = make_array("URL", url,
                     "Installed version", version,
                     "Fixed version", fix
                    );
  order = make_list("URL", "Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING, sqli:TRUE);
  exit(0);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url, version);
