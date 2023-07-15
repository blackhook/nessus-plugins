#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151128);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"VMware Carbon Black App Control Unsupported Version Detection");

  script_set_attribute(attribute:"synopsis", value:
"A system security agent running on the remote host is no longer
supported.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
VMware Carbon Black App Control, formerly known as Cb Protection
and Bit9 Parity, on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # https://community.carbonblack.com/t5/Documentation-Downloads/Carbon-Black-Product-Release-Lifecycle-Status/ta-p/39757
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17b7aaa6");
  # https://community.carbonblack.com/t5/Documentation-Downloads/Carbon-Black-Product-Support-Lifecycle-Policy/ta-p/35502
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?94aff410");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of VMware Carbon Black App Control that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported software.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:vmware:carbon_black_app_control");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:carbonblack:protection");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_carbon_black_app_control_web_console_detect.nbin", "vmware_carbon_black_app_control_win_installed.nbin");
  script_require_keys("installed_sw/VMware Carbon Black App Control");

  exit(0);
}

include('http.inc');
include('install_func.inc');

var app = 'VMware Carbon Black App Control';

var install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE, combined:TRUE);

var ver  = install['version'];
var path = install['path'];
var port = install['port'];

if (!empty_or_null(port) && get_kb_item(strcat('www/', port, '/webapp_installed'))) 
  path = build_url(port:port, qs:path);

if (!port) port = get_kb_item('SMB/transport');
if (!port) port = 445;

# Versions 1.x - 8.1.x
if (ver !~ "^(([1-7]|8\.[01])\.)")
  audit(AUDIT_LISTEN_NOT_VULN, app, port, ver);

register_unsupported_product(
  product_name : app,
  cpe_base     : 'vmware:carbon_black_app_control',
  is_custom_cpe: TRUE,
  version      : ver
);

report = strcat(
  '\n  Path              : ', path,
  '\n  Installed version : ', ver,
  '\n');

security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
