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
  script_id(105585);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/04");

  script_cve_id(
    "CVE-2018-0741",
    "CVE-2018-0747",
    "CVE-2018-0748",
    "CVE-2018-0749",
    "CVE-2018-0750"
  );
  script_xref(name:"MSKB", value:"4056942");
  script_xref(name:"MSFT", value:"MS18-4056942");
  script_xref(name:"MSKB", value:"4056613");
  script_xref(name:"MSFT", value:"MS18-4056613");
  script_xref(name:"MSKB", value:"4056615");
  script_xref(name:"MSFT", value:"MS18-4056615");
  script_xref(name:"MSKB", value:"4056759");
  script_xref(name:"MSFT", value:"MS18-4056759");
  script_xref(name:"MSKB", value:"4056944");
  script_xref(name:"MSFT", value:"MS18-4056944");
  script_xref(name:"MSKB", value:"4056941");
  script_xref(name:"MSFT", value:"MS18-4056941");

  script_name(english:"Windows 2008 January 3 2018 Multiple Security Updates");
  script_summary(english:"Checks the existence of Windows Server 2008 January 3 2018 Patches.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing multiple security updates released
on 2018/01/03. It is, therefore, affected by multiple
vulnerabilities :

  - An information disclosure vulnerabilities exists in the way that
    the Color Management Module (ICM32.dll) handles objects in
    memory. This vulnerability allows an attacker to retrieve
    information to bypass usermode ASLR (Address Space Layout
    Randomization) on a targeted system. By itself, the information
    disclosure does not allow arbitrary code execution. However, it
    could allow arbitrary code to be run if the attacker uses it in
    combination with another vulnerability. (CVE-2018-0741)

  - An information disclosure vulnerability exists in the Windows
    kernel that could allow an attacker to retrieve information that
    could lead to a Kernel Address Space Layout Randomization (ASLR)
    bypass. (CVE-2018-0747)

  - An elevation of privilege vulnerability exists in the way that
    the Windows Kernel API enforces permissions. An attacker who
    successfully exploits the vulnerability could impersonate
    processes, interject cross-process communication, or interrupt
    system functionality. (CVE-2018-0748)

  - An elevation of privilege vulnerability exists in the Microsoft
    Server Message Block (SMB) server when an attacker who has valid
    credentials attempts to open a specially crafted file over the
    SMB protocol on the same machine. An attacker who successfully
    exploits this vulnerability could bypass certain security checks
    in the operating system. (CVE-2018-0749)

  - A Win32k information disclosure vulnerability exists when the
    Windows GDI component improperly discloses kernel memory
    addresses. An attacker who successfully exploits the
    vulnerability could obtain information to further compromise the
    user's system. (CVE-2018-0750)

  - An information disclosure vulnerability exists in Adobe Type
    Manager Font Driver (ATMFD.dll) when it fails to properly handle
    objects in memory. An attacker who successfully exploits the
    vulnerability could obtain information to enable the attacker to
    further compromise the user's system.");
  # https://support.microsoft.com/en-sg/help/4056942/security-update-for-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee02a5e1");
  # https://support.microsoft.com/en-us/help/4056613/security-update-for-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b7618d8f");
  # https://support.microsoft.com/en-us/help/4056615/security-update-for-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14fd3757");
  # https://support.microsoft.com/en-ca/help/4056759/security-update-for-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10972e7d");
  # https://support.microsoft.com/en-us/help/4056944/security-update-for-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a3717b24");
  # https://support.microsoft.com/en-us/help/4056941/security-update-for-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7fd20780");
  script_set_attribute(attribute:"solution", value:
"Apply the following security updates :

  - 4056942
  - 4056613
  - 4056615
  - 4056759
  - 4056944
  - 4056941");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0749");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/04");

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

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS18-01';

kbs = make_list(
  "4056942",
  "4056613",
  "4056615",
  "4056759",
  "4056944",
  "4056941"
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

# KBs only apply to Windows 2008
if (hotfix_check_sp_range(vista:'2') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Vista" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

systemroot = hotfix_get_systemroot();
if (!systemroot) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');

port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

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

# 4056942
files = list_dir(basedir:winsxs, level:0, dir_pat:"icm-base_31bf3856ad364e35", file_pat:"^icm32\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24259'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4056942", session:the_session);

# 4056613
files = list_dir(basedir:winsxs, level:0, dir_pat:"os-kernel_31bf3856ad364e35", file_pat:"^ntoskrnl\.exe$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24262'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4056613", session:the_session);

# 4056615
files = list_dir(basedir:winsxs, level:0, dir_pat:"ntfs_31bf3856ad364e35", file_pat:"^ntfs\.sys$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24262'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4056615", session:the_session);

# 4056759
files = list_dir(basedir:winsxs, level:0, dir_pat:"netevent_31bf3856ad364e35", file_pat:"^netevent\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24262'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4056759", session:the_session);

# 4056944
files = list_dir(basedir:winsxs, level:0, dir_pat:"win32k_31bf3856ad364e35", file_pat:"^win32k\.sys$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24259'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4056944", session:the_session);

# 4056941
files = list_dir(basedir:winsxs, level:0, dir_pat:"gdi_31bf3856ad364e35", file_pat:"^atmfd\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('5.1.2.253'),
                            max_versions:make_list('5.1.2.99999'),
                            bulletin:bulletin,
                            kb:"4056941", session:the_session);

if (vuln > 0)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
