#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100616);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_xref(name:"IAVA", value:"0001-A-0627");

  script_name(english:"Zabbix Unsupported Version Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of Zabbix.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Zabbix on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.zabbix.com/life_cycle_and_release_policy");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Zabbix that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zabbix:zabbix");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2022 Tenable Network Security, Inc.");

  script_dependencies("zabbix_frontend_detect.nasl");
  script_require_keys("installed_sw/zabbix", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "zabbix";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
install_url = build_url(port:port, qs:dir);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

eol_date = NULL;
eol_url  = "https://www.zabbix.com/life_cycle_and_release_policy";
supported_versions = "2.2.x / 3.0.x / 3.2.x / 3.4.x";
eol_dates = make_array(
  "^2\.0($|[^0-9])"    , "2017/05/01",
  "^3\.2($|[^0-9])"    , "2017/04/01",
  "^2\.4($|[^0-9])"    , "2016/04/01",
  "^[0-1]\."           , ""
);

foreach regex (keys(eol_dates))
{
  if (version !~ regex) continue;
  eol_date = eol_dates[regex];
  break;
}

if (!isnull(eol_date))
{
  register_unsupported_product(product_name:app,
                               cpe_base:"zabbix:zabbix", version:version);

  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version  +
             '\n  EOL date          : ' + eol_date +
             '\n  EOL URL           : ' + eol_url  +
             '\n  Supported version : ' + supported_versions +
             '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Zabbix", port, version);
