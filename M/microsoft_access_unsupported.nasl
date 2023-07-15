#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102082);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/28");

  script_xref(name:"IAVA", value:"0001-A-0553");

  script_name(english:"Microsoft Access Unsupported Version Detection");
  script_summary(english:"Checks the Microsoft Access version.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Microsoft Access installed on the remote Windows host
is no longer supported.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Microsoft Access on the remote Windows host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # https://support.microsoft.com/lifecycle/search?sort=PN&alpha=Microsoft%20Access
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db216c69");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Microsoft Access that is currently
supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported software.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:access");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");

  script_dependencies("microsoft_access_installed.nbin");
  script_require_keys("installed_sw/Microsoft Access");

  exit(0);
}

include('misc_func.inc');
include('install_func.inc');

var app_name = 'Microsoft Access';
var port     = get_kb_item('SMB/transport');
if (!port) port = 445;

var installs = get_installs(app_name:app_name, port:port, exit_if_not_found:TRUE);
var cpe      = 'microsoft:access';

# Initialize supported_info array
var supported_info;
supported_info['95']['supported_sp'] = -1;
supported_info['97']['supported_sp'] = -1;

supported_info['2000']['supported_sp'] = -1;
supported_info['2002']['supported_sp'] = -1;
supported_info['2003']['supported_sp'] = -1;
supported_info['2007']['supported_sp'] = -1;
supported_info['2010']['supported_sp'] = -1;

# Version info from
# http://www.fmsinc.com/microsoftaccess/history/versions.htm


supported_info['2013']['supported_sp']      = 1;
supported_info['2013']['supported_ver']     = '15.0.4569.1506';

supported_info['2016']['supported_sp']      = 0;
supported_info['2016']['supported_ver']     = '16.0.4229.1024';

### Main

var info = '';
var vuln = 0;

var install, product, path, supported_sp, supported_version, supported_version_text, verbose_version, s;

foreach install(installs[1])
{
  product = install['Product'];
  if(isnull(product)) continue;

  path       = install['path'];
  sp         = install['sp'];
  version    = install['version'];
  display_sp = install['Service Pack'];

  supported_sp      = supported_info[product]['supported_sp'];
  supported_version = supported_info[product]['supported_ver'];

  supported_version_text = '';
  if (supported_sp < 0)
    supported_version_text = 'This version is no longer supported.';
  else if (!isnull(sp) && int(sp) < supported_sp)
    supported_version_text = supported_version + ' (' + product + ' SP' + supported_sp + ')';

  if (empty_or_null(supported_version_text)) continue;

  if (sp != UNKNOWN_VER && !empty_or_null(sp))
    verbose_version = version + ' (' + product + ' ' + display_sp + ')';
  else
    verbose_version = version + ' (' + product + ')';

  register_unsupported_product(product_name:app_name, version:version,
                               cpe_base:cpe);

  info += '\n  Path                      : ' + path +
          '\n  Installed version         : ' + verbose_version +
          '\n  Minimum supported version : ' + supported_version_text +
          '\n';
  vuln++;
}

if (vuln == 0)
  audit(AUDIT_HOST_NOT, 'affected');

if (vuln > 1) s = 's were';
else s = ' was';

report +=
  '\n' + 'The following unsupported ' + app_name + ' installation' + s + ' detected on' +
  '\n' + 'the remote host :' +
  '\n' + info +
  '\n';

security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
