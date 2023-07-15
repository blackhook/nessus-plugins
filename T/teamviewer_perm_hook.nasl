#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(105074);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/24");


  script_name(english:"TeamViewer Permissions Vulnerability (Windows)");
  script_summary(english:"Checks versions of TeamViewer");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a program that is affected by a
permissions vulnerability.");

  script_set_attribute(attribute:"description", value:
"According to its version number, the TeamViewer install on the remote
Windows host is a version prior to 11.0.89975, 12.0.89970, or 13.0.5640.
It is, therefore, affected by a permissions vulnerability than can result
in unauthorized remote control.

During an authenticated connection it may be possible for an attacker to 
control the mouse without regard for the server's current control setting. 
This can be exploited from both the viewer and presenter roles, enabling the 
viewer to control the presenters mouse or enabling the 'switch sides' feature without 
requiring the client to agree.
");

  #https://www.teamviewer.com/en/company/press/teamviewer-releases-hotfix-for-permission-hook-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?049e3175");
  script_set_attribute(attribute:"see_also", value:"https://threatpost.com/teamviewer-rushes-fix-for-permissions-bug/129096/");
  script_set_attribute(attribute:"see_also", value:"https://github.com/gellin/TeamViewer_Permissions_Hook_V1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to TeamViewer 11.0.89975 / 12.0.89970 / 13.0.5640 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Manual analysis of the vulnerability");


  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:teamviewer:teamviewer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2020 Tenable Network Security, Inc.");

  script_dependencies("teamviewer_detect.nasl");
  script_require_keys("SMB/TeamViewer/Installed");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("audit.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");


get_kb_item_or_exit('SMB/TeamViewer/Installed');
winver = get_kb_item_or_exit('SMB/WindowsVersion');

installs = get_kb_list('SMB/TeamViewer/*');

report = NULL;
fixed_version = "";
foreach install (keys(installs))
{
  if ('Install' >< install) continue;
  version = install - 'SMB/TeamViewer/';
  if (version =~ '^11\\.') fixed_version = "11.0.89975";
  if (version =~ '^12\\.') fixed_version = "12.0.89970";
  if (version =~ '^13\\.') fixed_version = "13.0.5640";
  if (version =~ '(^11\\.|^12\\.|^13\\.)' && ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
  {
    path = installs[install];
    report +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
  }
}

if (isnull(report)) exit(0, 'No vulnerable TeamViewer installs were detected.');

# If there is a vulnerable version installed, make sure Remote Access is enabled
# unless we're paranoid
name   = kb_smb_name();
port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

if (report_paranoia < 2)
{
  remoteaccess = FALSE;


  if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:'IPC$');
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, "IPC$");
  }
  hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
  if (isnull(hklm))
  {
    NetUseDel();
    audit(AUDIT_REG_FAIL);
  }

  key = 'SOFTWARE\\TeamViewer';
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:'Always_Online');
    if (!isnull(value)) remoteaccess = value[1];
    RegCloseKey(handle:key_h);
  }
  RegCloseKey(handle:hklm);
  NetUseDel();
  if (!remoteaccess) exit(0, 'The remote TeamViewer install is not affected because Remote Access is disabled.');
}
else
{
  report +=
    '  Comments         : ' +
    '\n  Note though that Nessus did not check whether \'Remote Access\' has' +
    '\n  been enabled because of the Report Paranoia setting in effect when' +
    '\n  this scan was run.\n';
}

if (report_verbosity > 0) security_warning(port:port, extra:report);
else security_warning(port);
exit(0);
