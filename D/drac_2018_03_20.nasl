#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109208);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-1207", "CVE-2018-1211", "CVE-2018-1000116");
  script_bugtraq_id(103694, 103768);

  script_name(english:"Dell iDRAC Products Multiple Vulnerabilities (Mar 2018)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running iDRAC7 or iDRAC8 with a firmware version 
prior to 2.52.52.52 and is therefore affected by multiple 
vulnerabilities.");
  # http://en.community.dell.com/techcenter/extras/m/white_papers/20485410
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6063b726");
  script_set_attribute(attribute:"solution", value:
"Update the iDRAC firmware to 2.52.52.52 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1207");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:remote_access_card");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:idrac7");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:idrac8");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("drac_detect.nasl");
  script_require_keys("installed_sw/iDRAC");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "iDRAC";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:443, embedded:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
fw_version = install['Firmware Version'];
install_url = build_url(port:port, qs:dir);

if (version !~ "^(7|8)")
  audit(AUDIT_WRONG_WEB_SERVER, port, "Neither iDRAC7 nor iDRAC8 and therefore is not affected");

fix = '2.52.52.52';

if(ver_compare(ver:fw_version, fix:"1.0", strict:FALSE) >= 1 && ver_compare(ver:fw_version, fix:fix, strict:FALSE) == -1)
{
  items = make_array(
    "URL", install_url,
    "iDRAC version", version,
    "Firmware version", fw_version,
    "Fixed version", fix
  );
  order = make_list("URL", "iDRAC version", "Firmware version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app + version, install_url, fw_version);
}
