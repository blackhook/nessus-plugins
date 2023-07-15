#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109651);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2018-0824",
    "CVE-2018-0886",
    "CVE-2018-0959",
    "CVE-2018-8120",
    "CVE-2018-8124",
    "CVE-2018-8164",
    "CVE-2018-8166",
    "CVE-2018-8167",
    "CVE-2018-8174",
    "CVE-2018-8897"
  );
  script_bugtraq_id(
    103998,
    104030,
    104031,
    104033,
    104034,
    104037,
    104063,
    104071
  );
  script_xref(name:"MSKB", value:"4056564");
  script_xref(name:"MSKB", value:"4094079");
  script_xref(name:"MSKB", value:"4101477");
  script_xref(name:"MSKB", value:"4130944");
  script_xref(name:"MSKB", value:"4131188");
  script_xref(name:"MSKB", value:"4134651");
  script_xref(name:"MSFT", value:"MS18-4056564");
  script_xref(name:"MSFT", value:"MS18-4094079");
  script_xref(name:"MSFT", value:"MS18-4101477");
  script_xref(name:"MSFT", value:"MS18-4130944");
  script_xref(name:"MSFT", value:"MS18-4131188");
  script_xref(name:"MSFT", value:"MS18-4134651");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/08/15");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/05");

  script_name(english:"Security Updates for Windows Server 2008 (May 2018)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security updates. It is,
therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists in the Credential
    Security Support Provider protocol (CredSSP). An attacker who
    successfully exploits this vulnerability could relay user
    credentials and use them to execute code on the target host.
    (CVE-2018-0886)

  - An elevation of privilege vulnerability exists when the
    Windows kernel fails to properly handle objects in
    memory. An attacker who successfully exploited this
    vulnerability could run arbitrary code in kernel mode.
    An attacker could then install programs; view, change,
    or delete data; or create new accounts with full user
    rights.  (CVE-2018-8897)

  - An elevation of privilege vulnerability exists when the
    Windows Common Log File System (CLFS) driver improperly
    handles objects in memory. An attacker who successfully
    exploited this vulnerability could run processes in an
    elevated context.  (CVE-2018-8167)

  - An elevation of privilege vulnerability exists in
    Windows when the Win32k component fails to properly
    handle objects in memory. An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    kernel mode. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights.  (CVE-2018-8120, CVE-2018-8124,
    CVE-2018-8164, CVE-2018-8166)

  - A remote code execution vulnerability exists in
    &quot;Microsoft COM for Windows&quot; when it fails to
    properly handle serialized objects. An attacker who
    successfully exploited the vulnerability could use a
    specially crafted file or script to perform actions. In
    an email attack scenario, an attacker could exploit the
    vulnerability by sending the specially crafted file to
    the user and convincing the user to open the file.
    (CVE-2018-0824)

  - A remote code execution vulnerability exists in the way
    that the VBScript engine handles objects in memory. The
    vulnerability could corrupt memory in such a way that an
    attacker could execute arbitrary code in the context of
    the current user. An attacker who successfully exploited
    the vulnerability could gain the same user rights as the
    current user.  (CVE-2018-8174)

  - A remote code execution vulnerability exists when
    Windows Hyper-V on a host server fails to properly
    validate input from an authenticated user on a guest
    operating system.  (CVE-2018-0959)");
  # https://support.microsoft.com/en-us/help/4056564/security-update-for-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b5f5c446");
  # https://support.microsoft.com/en-us/help/4094079/security-update-for-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?772e96fe");
  # https://support.microsoft.com/en-us/help/4134651/description-of-the-security-update-for-vulnerabilities-in-windows
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ebb568d");
  # https://support.microsoft.com/en-us/help/4131188/win32k-elevation-of-privilege-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f9bcdfa");
  # https://support.microsoft.com/en-us/help/4130944/windows-common-log-file-system-driver-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?28ae25e4");
  # https://support.microsoft.com/en-us/help/4101477/microsoft-com-for-windows-remote-code-execution-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?90a897a3");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Windows Server 2008.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8174");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-8897");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Windows POP/MOV SS Local Privilege Elevation Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "wmi_enum_server_features.nbin");
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

bulletin = 'MS18-05';

kbs = make_list(
  "4056564",
  "4094079",
  "4101477",
  "4130944",
  "4131188",
  "4134651"
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
files = list_dir(basedir:winsxs, level:0, dir_pat:"security-schannel_31bf3856ad364e35", file_pat:"^schannel\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24383'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4056564", session:the_session);


# KB4094079 (hyper-v ; 64bit only)
files = list_dir(basedir:winsxs, level:0, dir_pat:"hyper-v-storage_31bf3856ad364e35", file_pat:"^synthstor\.dll$", max_recurse:1);
if (
  arch == "x64" &&
  (get_kb_item('WMI/server_feature/20') || report_paranoia == 2 ) &&
  hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24362'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4094079", session:the_session)
)
{
  vuln++;
}

# KB4101477
files = list_dir(basedir:winsxs, level:0, dir_pat:"catsrvut-comsvcs_31bf3856ad364e35", file_pat:"^catsrvut\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('2001.12.6932.24363'),
                            max_versions:make_list('2001.12.6932.99999'),
                            bulletin:bulletin,
                            kb:"4101477", session:the_session);


# KB4130944
files = list_dir(basedir:winsxs, level:0, dir_pat:"commonlog_31bf3856ad364e35", file_pat:"^clfs\.sys$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24361'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4130944", session:the_session);

# KB4131188
files = list_dir(basedir:winsxs, level:0, dir_pat:"win32k_31bf3856ad364e35", file_pat:"^win32k\.sys$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24363'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4131188", session:the_session);

# KB4134651
files = list_dir(basedir:winsxs, level:0, dir_pat:"ntdll_31bf3856ad364e35", file_pat:"^ntdll\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24367'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4134651", session:the_session);

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
