#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(51191);
  script_version("1.13");
  script_cvs_date("Date: 2018/11/15 20:50:26");

  script_cve_id("CVE-2010-2602");
  script_bugtraq_id(45392);
  script_xref(name:"Secunia", value:"35632");

  script_name(english:"BlackBerry Enterprise Server / Attachment Service PDF Distiller Buffer Overflow (KB24761)");
  script_summary(english:"Checks version and looks for workaround");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a
buffer overflow vulnerability.");

  script_set_attribute(attribute:"description", value:
"The version of BlackBerry Enterprise Server on the remote host is
reportedly affected by a buffer overflow vulnerability in the PDF
distiller component of the BlackBerry Attachment Service. By sending a
specially crafted PDF file and having it opened on a BlackBerry
smartphone, an attacker may be able to execute arbitrary code on the
system that runs the BlackBerry Attachment Service.");

  script_set_attribute(attribute:"see_also", value:"https://salesforce.services.blackberry.com/kbredirect/viewContent.do?externalId=KB24761");
  script_set_attribute(attribute:"solution", value:"Apply the vendor-supplied patches.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rim:blackberry_enterprise_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2018 Tenable Network Security, Inc.");

  script_dependencies("blackberry_es_installed.nasl", "smb_hotfixes.nasl");
  script_require_keys("BlackBerry_ES/Product", "BlackBerry_ES/Path", "BlackBerry_ES/Version", "BlackBerry_ES/AttachmentServer", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");

prod = get_kb_item_or_exit("BlackBerry_ES/Product");
version = get_kb_item_or_exit("BlackBerry_ES/Version");
path = get_kb_item_or_exit("BlackBerry_ES/Path");
if (isnull(get_kb_item("BlackBerry_ES/AttachmentServer"))) exit(0, "The host is not affected because BlackBerry Attachment Server isn't installed.");

# Exit unless it looks like a vulnerable version
if (
  ("Enterprise Server" >< prod && version !~ '^(4\\.1\\.[3-7]|5\\.0)') ||
  ("Professional Software" >< prod && version !~ '^([0-3]\\..*|4\\.(0\\.|1\\.[0-3][^0-9]))')
) exit (0, prod+" "+version+" is installed and not affected.");

BES4    = 0;
BES4Pro = 0;
BES5    = 0;
fix = NULL;

if      ("Enterprise Server" >< prod && version =~ '4\\.1')
{
  BES4 = 1;
  if (version =~ '^4\\.1\\.[0-5]\\.') fix = 'n/a';
  else if (version =~ '^4\\.1\\.6\\.') fix = '4.1.6.20';
  else if (version =~ '^4\\.1\\.7\\.') fix = '4.1.7.12';
}
else if ("Enterprise Server" >< prod && version =~ '5\\.0')
{
  BES5 = 1;
  if (version =~ '^5\\.0\\.0\\.') fix = '5.0.0.60';
  else if (version =~ '^5\\.0\\.1\\.') fix = '5.0.1.38';
  else if (version =~ '^5\\.0\\.2\\.') fix = '5.0.2.20';
}
else if ("Professional Server" >< prod)
{
  BES4Pro = 1;
  fix = 'n/a';
}

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Connect to the appropriate share.
port     = kb_smb_transport();
login    = kb_smb_login();
pass     = kb_smb_password();
domain   = kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Could not connect to IPC$ share.");
}

# Connect to the remote registry
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Could not connect to the remote registry.");
}

# Determine whether the workaround has been implemented
info = "";

if (report_paranoia > 1)
{
  info =
    '\nNote, though that Nessus did not check whether the workaround has'+
    '\nbeen implemented because of the Report Paranoia setting in effected'+
    '\nwhen this scan was run.\n';
}
else
{
  if (BES4)
  {
    key = "SOFTWARE\Research In Motion\BBAttachServer\BBAttachBESEXtension";
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      item = RegQueryValue(handle:key_h, item:"BBAttachFormatList");
      if (!isnull(item))
      {
        formats = item[1];
        if ("|pdf|" >< formats) info += '\n  - The format extensions field includes \'pdf\'.';
      }
      RegCloseKey(handle:key_h);
    }
  }

  key = "SOFTWARE\Research In Motion\BBAttachEngine\Distillers\LoadPDFDistiller";
  key_h = RegOpenKey(handle:key_h, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:"Enabled");
    if (!isnull(item))
    {
      enabled = item[1];
      if (enabled) info += '\n  - The PDF distiller is enabled.';
    }
    RegCloseKey(handle:key_h);
  }

  if (info)
  {
    if (BES4 || max_index(split(info)) > 1)
    {
      info =
        '\nNessus has determined that the workaround described in the' +
        '\nvendor\'s advisory has not been implemented because :' +
        '\n' +
        info;
    }
    else
    {
      info =
        '\nNessus had determined that the workaround described in the' +
        '\nvendor\'s advisory has only been partially implemented' +
        '\nbecause :' +
        '\n' +
        info;
    }
  }
}
RegCloseKey(handle:hklm);

# Check if the patch for BlackBerry ES was applied.
vuln = FALSE;
if (!isnull(path))
{
  share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:path);
  path2 = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\', string:path);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc == 1)
  {
    dlls = make_list(
      'AttachServer\\BBDecorator\\BBRenderingDecorator.dll',
      'AttachServer\\BBDecorator\\BBXRenderingDecorator.dll',
      'AttachServer\\BBDistiller\\BBDM_PDF.dll'
    );

    dll_probs = '';
    foreach dll (dlls)
    {
      fh = CreateFile(
        file:path2+dll,
        desired_access:GENERIC_READ,
        file_attributes:FILE_ATTRIBUTE_NORMAL,
        share_mode:FILE_SHARE_READ,
        create_disposition:OPEN_EXISTING
      );
      if (!isnull(fh))
      {
        ver = GetFileVersion(handle:fh);
        if (ver)
        {
          if (
            (
              (
                BES4 && ver[0] == 4 && ver[1] == 1 &&
                (
                  (ver[2] < 6) ||
                  (ver[2] == 6 && ver[3] < 20) ||
                  (ver[2] == 7 && ver[3] < 12)
                )
              ) ||
              (
                BES5 && ver[0] == 5 && ver[1] == 0 &&
                (
                  (ver[2] == 0 && ver[3] < 60) ||
                  (ver[2] == 1 && ver[3] < 38) ||
                  (ver[2] == 2 && ver[3] < 20)
                )
              ) ||
              (
                BESPro &&
                (
                  (ver[0] < 4) ||
                  (ver[0] == 4 && ver[1] < 1) ||
                  (ver[0] == 4 && ver[1] == 1 && ver[2] < 4) ||
                  (ver[0] == 4 && ver[1] == 1 && ver[2] == 4 && ver[3] <= 24)
                )
              )
            )
          )
          {
            file_version = join(sep:'.', ver);
            dll_probs += '  - ' + dll + ' (version ' + file_version + ')\n';
            vuln = TRUE;
          }
        }
        else dll_probs += '  - ' + dll + ' (unknown version)\n';

        CloseFile(handle:fh);
      }
      else dll_probs += '  - ' + dll + ' (unable to open file)\n';
    }

    # There's no vulnerability if we could determine the DLLs have been patched.
    if (!dll_probs) info = "";
    # Otherwise if there's at least one patched file...
    else if (max_index(split(dll_probs)) <= max_index(keys(dlls)))
    {
      if (max_index(split(dll_probs)) > 1) s = "s are";
      else s = " is";

      if (vuln)
      {
        info = info +
          '\nIn addition, it appears that the patch has not been' +
          '\ninstalled completely as the following file' + s + ' still' +
          '\nvulnerable :\n' +
          '\n' +
          dll_probs;
      }
      else exit(1, "There was an issue accessing at least one of the affected DLLs.");
    }
  }
}
NetUseDel();

# Report if an issue was found
if (info)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Product  : ' + prod +
      '\n  Version  : ' + version +
      '\n  Fix      : ' + fix +
      '\n  Comments : ' + str_replace(find:'\n', replace:'\n                ', string:info);
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, prod + ' ' + version + ' is installed and not affected.');
