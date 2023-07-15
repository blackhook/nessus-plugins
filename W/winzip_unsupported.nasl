#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(78675);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/28");

  script_xref(name:"IAVA", value:"0001-A-0623");

  script_name(english:"WinZip Unsupported Version Detection");

  script_set_attribute(attribute:"synopsis", value:
"A file compression and decompression application installed on the
remote host is no longer supported.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
WinZip on the remote Windows host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www.winzip.com");
  script_set_attribute(attribute:"see_also", value:"http://kb.winzip.com/kb/entry/132/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of WinZip that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Default unsupported software score.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:winzip:winzip");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("winzip_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/WinZip");

  exit(0);
}

include('install_func.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var appname = 'WinZip';

var install = get_single_install(app_name:appname);
var path = install['path'];
var disp_ver = install['display_version'];

var ver = pregmatch(string:disp_ver, pattern:"^([0-9.]+)[^0-9.].*");
if(empty_or_null(ver)) audit(AUDIT_UNKNOWN_APP_VER, appname);
else ver = ver[1];

var currently_supported = '22.x - 25.x';
var currently_unsupported_cutoff = '22.0';

var port, report;
if (ver_compare(ver:ver, fix:currently_unsupported_cutoff, strict:FALSE) < 0)
{
  register_unsupported_product(product_name:"WinZip",
                               cpe_base:"winzip:winzip", version:disp_ver);

  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  report =
    '\n  Path               : ' + path +
    '\n  Installed version  : ' + disp_ver +
    '\n  Supported versions : ' + currently_supported +
    '\n  EOL URL            : http://kb.winzip.com/kb/entry/132/' +
    '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, ver, path);
