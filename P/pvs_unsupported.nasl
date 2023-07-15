#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(71459);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_xref(name:"IAVA", value:"0001-A-0603");

  script_name(english:"Tenable Passive Vulnerability Scanner Unsupported Version Detection (remote check)");

  script_set_attribute(attribute:"synopsis", value:
"A vulnerability scanner application running on the remote host is no
longer supported.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Tenable Passive Vulnerability Scanner (PVS) on the remote host is no
longer supported. The product name has subsequently been changed to Nessus Network Monitor (NNM).

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # https://www.tenable.com/downloads
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?acfa0664");
  # https://tenable.my.salesforce.com/sfc/p/#300000000pZp/a/3a000000gPnK/Gu5PvUfKyV_gL0LdpNGgSdJ0PLKk15KPFcucY_BGlek
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f1e381f2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Tenable Nessus Network Monitor (NNM) that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:tenable:pvs");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 Tenable Network Security, Inc.");

  script_dependencies("pvs_proxy_detect.nasl");
  script_require_keys("www/pvs");
  script_require_ports("Services/www", 8835);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

port = get_http_port(default:8835);

install = get_install_from_kb(appname:"pvs", port:port, exit_on_fail:TRUE);
dir = install['dir'];
install_loc = build_url(port:port, qs:dir + '/');

version = install['ver'];
if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "PVS", install_loc);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i < max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] < 5 || (ver[0] == 5 && ver[1] < 4) )
{
  register_unsupported_product(product_name:"Tenable PVS",
                               cpe_base:"tenable:pvs", version:version);

  report =
    '\n  Installed version  : ' + version +
    '\n  Supported versions : Upgrade to Nessus Network Monitor (NNM)\n';

  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
  exit(0);
}
else exit(0, 'The PVS ' + version + ' server listening on port ' + port + ' is currently supported.');
