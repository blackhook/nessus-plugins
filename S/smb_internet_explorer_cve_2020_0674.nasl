#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 13/02/2020 Deprecated by smb_nt_ms20_feb_internet_explorer.nasl
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#
include('compat.inc');

if (description)
{
  script_id(133147);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/30");

  script_cve_id("CVE-2020-0674");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Internet Explorer Scripting Engine Memory Corruption Vulnerability (CVE-2020-0674) (Deprecated)");
  script_summary(english:"Checks the Internet Explorer version and the file permissions of jscript.dll");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin was a workaround for unpatched vulnerability CVE-2020-0674 which was patched in the Feb 2020 rollups.
The plugin smb_nt_ms20_feb_internet_explorer.nasl (plugin ID 133619) includes the check for the new patch for this 
vulnerability.");
  # https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/ADV200001
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ef3f446");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0674");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/IE/Version");
  script_require_ports(139, 445);

  exit(0);
}
exit(0, "This plugin has been deprecated. Use smb_nt_ms20_feb_internet_explorer.nasl (plugin ID 133619) instead.");

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('smb_func.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_hotfixes.inc');

##
# Gets the DACL of the given file
#
# @anonparam fh handle of the file to obtain the DACL for
#
# @return DACL associated with 'fh'
# Taken from smb_insecure_service_permissions.nasl
##
function _get_dacl()
{
  local_var fh, sd, dacl;
  fh = _FCT_ANON_ARGS[0];

  sd = GetSecurityInfo(handle:fh, level:DACL_SECURITY_INFORMATION);
  if (isnull(sd))
    return NULL;

  dacl = sd[3];
  if (isnull(dacl))
    return NULL;

  dacl = parse_pdacl(blob:dacl);
  if (isnull(dacl))
    return NULL;

  return dacl;
}

##
# Checks if any user has access to jscript.dll
# Returns TRUE if yes, which indicates incomplete mitigation.
##
function _insecure_file_perms()
{
  local_var arch, path, perm_to_check, allowed, fh, dacl, ace, rights, type, sid, groups;
  local_var sysroot, path32, path64, paths, full_path, files;

  arch = get_kb_item('SMB/ARCH');
  sysroot = hotfix_get_systemroot();
  path32 = '\\System32\\jscript.dll';
  path64 = '\\SysWOW64\\jscript.dll';
  files = make_array();

  # default to checking both, since not finding syswow64 is
  # functionally the same as not having access here. 
  if(isnull(arch) || arch == 'x64')
    paths = [path32, path64];
  else paths = [path32];

  foreach path (paths)
  {
    allowed = make_array();
    full_path = sysroot + path;
    path =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:full_path);
    perm_to_check = FILE_READ_DATA;

    if (isnull(path)) continue;

    fh = CreateFile(
      file:path,
      desired_access:STANDARD_RIGHTS_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (isnull(fh)) continue;

    dacl = _get_dacl(fh);
    CloseFile(handle:fh);
    if (isnull(dacl)) continue;

    foreach ace (dacl)
    {
      ace = parse_dacl(blob:ace);
      if (isnull(ace)) continue;

      rights = ace[0];
      type = ace[3];
      sid = sid2string(sid:ace[1]);
      if (isnull(sid)) continue;
      if (
        type == ACCESS_ALLOWED_ACE_TYPE && rights & perm_to_check == perm_to_check &&
        (sid == '1-1-0' ||     # Everyone
        sid == '1-5-32-545' || # Users
        sid == '1-5-11')       # Authenticated Users
        )
        {
          allowed[sid] = TRUE;
        }
      else if (
        type == ACCESS_DENIED_ACE_TYPE && rights & perm_to_check == perm_to_check &&
        (sid == '1-1-0' ||      # Everyone
         sid == '1-5-32-545' || # Users
         sid == '1-5-11')       # Authenticated Users
        )
        {
          allowed[sid] = FALSE;
        }
    }
    # Owner of the file can see result for EVERYONE group when scanning
    # and only when the mitigation is active (i.e. EVERYONE = FALSE)
    # Other admins can't necessarily see that (even when mitigation active)
    # so we could be vuln if 1-1-0 isnull && 1-5-32-545 is allowed
    if(isnull(allowed['1-1-0']) && maxlen(allowed)>0)
    {
      files[full_path] = TRUE;
    }
    else if(allowed['1-1-0']==TRUE)
      files[full_path] = TRUE;
  }
  
  if(maxlen(files)>0)
    return files;
  return NULL;
}

get_kb_item_or_exit('SMB/Registry/Enumerated');
version = get_kb_item_or_exit('SMB/IE/Version');

#Checking IE Version
if (version !~ "^(9|10|11)\.")
    audit(AUDIT_HOST_NOT, 'affected');

#Login & access share to system
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();
port    =  kb_smb_transport();

if(! smb_session_init(report_access_trouble:FALSE)) audit(AUDIT_FN_FAIL, 'smb_session_init');

report = NULL;
share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

ret = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (isnull(ret) || ret == -1 || ret == 0)
{
    NetUseDel();
    audit(AUDIT_MISSING_CREDENTIALS, 'valid');
}

#Check if we have access to any file in system32
root = hotfix_get_systemroot();
kernel_path = root + '\\system32\\kernel32.dll';
kernel_path =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:kernel_path);
fh = CreateFile(
    file:kernel_path,
    desired_access:STANDARD_RIGHTS_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  ); 

if (isnull(fh))
{
  NetUseDel();
  audit(AUDIT_FN_FAIL, 'insecure_file_perms', 'No access granted for system32.');
}

#Check if anyone has read access to the files
files = _insecure_file_perms();

if (!empty_or_null(files))
{
    report = 'Access to the following files is permitted for a user or group on the system:\n\n';
    report += '  Internet Explorer Version: ' + version + '\n';
    foreach file (keys(files)){
      report += '  '+file+'\n';
    }
    report += '\nThis configuration indicates that Internet Explorer is vulnerable to CVE-2020-0674.\n';
    report += 'Refer to Microsoft advisory ADV200001 for more information and mitigation steps.\n';
}

NetUseDel();

if (isnull(report))
  audit(AUDIT_HOST_NOT, 'affected');

security_hole(port:port, extra:report);
