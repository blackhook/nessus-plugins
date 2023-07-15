#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#
include("compat.inc");

if (description)
{
  script_id(108300);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/04");

  script_cve_id(
    "CVE-2018-0811",
    "CVE-2018-0813",
    "CVE-2018-0814",
    "CVE-2018-0815",
    "CVE-2018-0816",
    "CVE-2018-0817",
    "CVE-2018-0868",
    "CVE-2018-0878",
    "CVE-2018-0883",
    "CVE-2018-0885",
    "CVE-2018-0886",
    "CVE-2018-0888",
    "CVE-2018-0894",
    "CVE-2018-0895",
    "CVE-2018-0896",
    "CVE-2018-0897",
    "CVE-2018-0898",
    "CVE-2018-0899",
    "CVE-2018-0900",
    "CVE-2018-0901",
    "CVE-2018-0904",
    "CVE-2018-0929",
    "CVE-2018-0935"
  );
  script_bugtraq_id(
    103230,
    103231,
    103232,
    103234,
    103236,
    103238,
    103240,
    103241,
    103242,
    103243,
    103244,
    103245,
    103246,
    103248,
    103249,
    103250,
    103251,
    103259,
    103261,
    103262,
    103265,
    103295,
    103298,
    103299,
    103309
  );
  script_xref(name:"MSKB", value:"4088827");
  script_xref(name:"MSKB", value:"4073011");
  script_xref(name:"MSKB", value:"4089344");
  script_xref(name:"MSKB", value:"4089175");
  script_xref(name:"MSKB", value:"4089453");
  script_xref(name:"MSKB", value:"4089229");
  script_xref(name:"MSKB", value:"4087398");
  script_xref(name:"MSKB", value:"4056564");
  script_xref(name:"MSFT", value:"MS18-4088827");
  script_xref(name:"MSFT", value:"MS18-4073011");
  script_xref(name:"MSFT", value:"MS18-4089344");
  script_xref(name:"MSFT", value:"MS18-4089175");
  script_xref(name:"MSFT", value:"MS18-4089453");
  script_xref(name:"MSFT", value:"MS18-4089229");
  script_xref(name:"MSFT", value:"MS18-4087398");
  script_xref(name:"MSFT", value:"MS18-4056564");

  script_name(english:"Security Updates for Windows Server 2008 (March 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security updates. It is,
therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists when
    Windows Remote Assistance incorrectly processes XML
    External Entities (XXE). An attacker who successfully
    exploited the vulnerability could obtain information to
    further compromise the users system.  (CVE-2018-0878)

  - An information disclosure vulnerability exists when
    Internet Explorer improperly handles objects in memory.
    An attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2018-0929)

  - A remote code execution vulnerability exists when
    Windows Shell does not properly validate file copy
    destinations. An attacker who successfully exploited the
    vulnerability could run arbitrary code in the context of
    the current user. If the current user is logged on with
    administrative user rights, an attacker could take
    control of the affected system. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights. Users whose
    accounts are configured to have fewer user rights on the
    system could be less impacted than users who operate
    with administrative user rights.  (CVE-2018-0883)


  - An information disclosure vulnerability exists when the
    Windows kernel improperly initializes objects in memory.
    (CVE-2018-0811, CVE-2018-0813, CVE-2018-0814)

  - A denial of service vulnerability exists when Microsoft
    Hyper-V Network Switch on a host server fails to
    properly validate input from a privileged user on a
    guest operating system. An attacker who successfully
    exploited the vulnerability could cause the host server
    to crash.  (CVE-2018-0885)

  - An information disclosure vulnerability exists in the
    Windows kernel that could allow an attacker to retrieve
    information that could lead to a Kernel Address Space
    Layout Randomization (ASLR) bypass. An attacker who
    successfully exploited the vulnerability could retrieve
    the memory address of a kernel object.  (CVE-2018-0894,
    CVE-2018-0895, CVE-2018-0896, CVE-2018-0897,
    CVE-2018-0898, CVE-2018-0899, CVE-2018-0900,
    CVE-2018-0901, CVE-2018-0904)

  - An elevation of privilege vulnerability exists in the
    Windows Installer when the Windows Installer fails to
    properly sanitize input leading to an insecure library
    loading behavior. A locally authenticated attacker could
    run arbitrary code with elevated system privileges. An
    attacker could then install programs; view, change, or
    delete data; or create new accounts with full user
    rights. The security update addresses the vulnerability
    by correcting the input sanitization error to preclude
    unintended elevation. (CVE-2018-0868)

  - A remote code execution vulnerability exists in the
    Credential Security Support Provider protocol (CredSSP).
    An attacker who successfully exploited this
    vulnerability could relay user credentials and use them
    to execute code on the target system. CredSSP is an
    authentication provider which processes authentication
    requests for other applications; any application which
    depends on CredSSP for authentication may be vulnerable
    to this type of attack. As an example of how an attacker
    would exploit this vulnerability against Remote Desktop
    Protocol, the attacker would need to run a specially
    crafted application and perform a man-in-the-middle
    attack against a Remote Desktop Protocol session. An
    attacker could then install programs; view, change, or
    delete data; or create new accounts with full user
    rights. The security update addresses the vulnerability
    by correcting how Credential Security Support Provider
    protocol (CredSSP) validates requests during the
    authentication process. To be fully protected against
    this vulnerability users must enable Group Policy
    settings on their systems and update their Remote
    Desktop clients. The Group Policy settings are disabled
    by default to prevent connectivity problems and users
    must follow the instructions documented HERE to be fully
    protected. (CVE-2018-0886)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Graphics Device Interface (GDI)
    handles objects in memory. An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    kernel mode. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights.  (CVE-2018-0815, CVE-2018-0816,
    CVE-2018-0817)

  - An information disclosure vulnerability exists when
    Windows Hyper-V on a host operating system fails to
    properly validate input from an authenticated user on a
    guest operating system.  (CVE-2018-0888)");
  # https://support.microsoft.com/en-us/help/4088827/security-update-for-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a503ac7d");
  # https://support.microsoft.com/en-us/help/4073011/security-update-for-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ad7c9d64");
  # https://support.microsoft.com/en-us/help/4089344/security-update-for-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee81d98b");
  # https://support.microsoft.com/en-us/help/4089175/security-update-for-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7b65cff");
  # https://support.microsoft.com/en-us/help/4089453/security-update-for-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7271c25b");
  # https://support.microsoft.com/en-us/help/4089229/security-update-for-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f32d175b");
  # https://support.microsoft.com/en-us/help/4087398/security-update-for-vulnerabilities-in-windows
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0db565f6");
  # https://support.microsoft.com/en-us/help/4056564/security-update-for-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b5f5c446");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4088827
  -KB4073011
  -KB4089344
  -KB4089175
  -KB4089453
  -KB4089229
  -KB4087398
  -KB4056564");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0886");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS18-03';

kbs = make_list(
  "4056564",
  "4073011",
  "4087398",
  "4088827",
  "4089175",
  "4089229",
  "4089344",
  "4089453"
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

# KBs only apply to Windows 2008
if (hotfix_check_sp_range(vista:'2') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Vista" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

systemroot = hotfix_get_systemroot();
if (!systemroot) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');

arch = get_kb_item_or_exit('SMB/ARCH', exit_code:1);

port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

# Fixing Remote Assistance FP
# Remote Assistance binaries come with Win 2008
# Microsoft only allows patching them if the "Feature" is installed
# We check the registry to see if Remote Assistance is enabled
# This requires IPC$ rather than winsxs
# See msra below
rc_ra = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc_ra != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, winsxs_share);
}

key_ra = "SYSTEM\CurrentControlSet\Control\Remote Assistance";
msra = false;
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (!isnull(hklm))
{
  out = RegOpenKey(handle:hklm, key:key_ra, mode:MAXIMUM_ALLOWED);
  if (!isnull(out)) 
  {
    msra = true;
    RegCloseKey(handle:out);
  }
  RegCloseKey(handle:hklm);
}
NetUseDel(close:FALSE);

# Resume regular plugin
winsxs = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\WinSxS", string:systemroot);
winsxs_share = hotfix_path2share(path:systemroot);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:winsxs_share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, winsxs_share);
}

the_session = make_array(
  'login',    login,
  'password', pass,
  'domain',   domain,
  'share',    winsxs_share
);

vuln = 0;

# KB4056564
files = list_dir(basedir:winsxs, level:0, dir_pat:"bcrypt-dll_31bf3856ad364e35", file_pat:"^bcrypt\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24123'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4056564", session:the_session);

# KB4073011 (hyper-v ; 64bit only)
files = list_dir(basedir:winsxs, level:0, dir_pat:"hyper-v-drivers_31bf3856ad364e35", file_pat:"^hvax64\.exe$", max_recurse:1);
if (
  arch == "x64" &&
  hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24302'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4073011", session:the_session)
)
{
  vuln++;
}

# KB4087398
files = list_dir(basedir:winsxs, level:0, dir_pat:"-lua_31bf3856ad364e35", file_pat:"^appinfo\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24299'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4087398", session:the_session);

# KB4088827
files = list_dir(basedir:winsxs, level:0, dir_pat:"hyper-v-stack_31bf3856ad364e35", file_pat:"^vmms\.exe$", max_recurse:1);
if (
  arch == "x64" &&
  hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24302'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4088827", session:the_session)
)
{
  vuln++;
}

# KB4089175
files = list_dir(basedir:winsxs, level:0, dir_pat:"zipfldr_31bf3856ad364e35", file_pat:"^zipfldr\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24305'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4089175", session:the_session);

# KB4089229
files = list_dir(basedir:winsxs, level:0, dir_pat:"acpi.inf.resources_31bf3856ad364e35", file_pat:"^acpi\.sys$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24311'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4089229", session:the_session);

# KB4089344
files = list_dir(basedir:winsxs, level:0, dir_pat:"win32k_31bf3856ad364e35", file_pat:"^win32k\.sys$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24321'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4089344", session:the_session);

# KB4089453
if (msra)
{
  files = list_dir(basedir:winsxs, level:0, dir_pat:"remoteassistance-exe_31bf3856ad364e35", file_pat:"^msra\.exe$", max_recurse:1);
  vuln += hotfix_check_winsxs(os:'6.0',
                              sp:2,
                              files:files,
                              versions:make_list('6.0.6002.24305'),
                              max_versions:make_list('6.0.6003.99999'),
                              bulletin:bulletin,
                              kb:"4089453", session:the_session);
}

if (vuln > 0)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
