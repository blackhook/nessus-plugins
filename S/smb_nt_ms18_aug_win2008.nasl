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
  script_id(111700);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/04");

  script_cve_id(
    "CVE-2018-3615",
    "CVE-2018-3620",
    "CVE-2018-3646",
    "CVE-2018-8339",
    "CVE-2018-8344",
    "CVE-2018-8345",
    "CVE-2018-8346",
    "CVE-2018-8348",
    "CVE-2018-8349",
    "CVE-2018-8394",
    "CVE-2018-8396",
    "CVE-2018-8397",
    "CVE-2018-8398"
  );
  script_bugtraq_id(
    104983,
    104984,
    104992,
    104994,
    104995,
    105001,
    105002,
    105027,
    105028,
    105030,
    105080
  );
  script_xref(name:"MSKB", value:"4338380");
  script_xref(name:"MSKB", value:"4340937");
  script_xref(name:"MSKB", value:"4340939");
  script_xref(name:"MSKB", value:"4341832");
  script_xref(name:"MSKB", value:"4343674");
  script_xref(name:"MSKB", value:"4344104");
  script_xref(name:"MSFT", value:"MS18-4338380");
  script_xref(name:"MSFT", value:"MS18-4340937");
  script_xref(name:"MSFT", value:"MS18-4340939");
  script_xref(name:"MSFT", value:"MS18-4341832");
  script_xref(name:"MSFT", value:"MS18-4343674");
  script_xref(name:"MSFT", value:"MS18-4344104");

  script_name(english:"Security Updates for Windows Server 2008 (August 2018) (Foreshadow)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security updates. It is,
therefore, affected by multiple vulnerabilities :

  - Errors exist related to microprocessors utilizing
    speculative execution and L1 data cache that could
    allow information disclosure. (CVE-2018-3615,
    CVE-2018-3620, CVE-2018-3646)

  - A remote code execution vulnerability exists when the
    Windows font library improperly handles specially
    crafted embedded fonts. An attacker who successfully
    exploited the vulnerability could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.  (CVE-2018-8344)

  - A remote code execution vulnerability exists in the way
    the scripting engine handles objects in memory in
    Microsoft browsers. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2018-8385)

  - A remote code execution vulnerability exists in
    Microsoft Windows that could allow remote code execution
    if a .LNK file is processed. An attacker who
    successfully exploited this vulnerability could gain the
    same user rights as the local user.  (CVE-2018-8345,
    CVE-2018-8346)

  - An information disclosure vulnerability exists when the
    Windows GDI component improperly discloses the contents
    of its memory. An attacker who successfully exploited
    the vulnerability could obtain information to further
    compromise the users system. There are multiple ways an
    attacker could exploit the vulnerability, such as by
    convincing a user to open a specially crafted document,
    or by convincing a user to visit an untrusted webpage.
    The security update addresses the vulnerability by
    correcting how the Windows GDI component handles objects
    in memory. (CVE-2018-8394, CVE-2018-8396, CVE-2018-8398)

  - A remote code execution vulnerability exists in the way
    that the Windows Graphics Device Interface (GDI) handles
    objects in the memory. An attacker who successfully
    exploited this vulnerability could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.  (CVE-2018-8397)

  - A remote code execution vulnerability exists in
    'Microsoft COM for Windows' when it fails to
    properly handle serialized objects. An attacker who
    successfully exploited the vulnerability could use a
    specially crafted file or script to perform actions. In
    an email attack scenario, an attacker could exploit the
    vulnerability by sending the specially crafted file to
    the user and convincing the user to open the file.
    (CVE-2018-8349)

  - An elevation of privilege vulnerability exists in the
    Windows Installer when the Windows Installer fails to
    properly sanitize input leading to an insecure library
    loading behavior. A locally authenticated attacker could
    run arbitrary code with elevated system privileges. An
    attacker could then install programs; view, change, or
    delete data; or create new accounts with full user
    rights. The security update addresses the vulnerability
    by correcting the input sanitization error to preclude
    unintended elevation. (CVE-2018-8339)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2018-8348)");
  # https://support.microsoft.com/en-us/help/4338380/security-update-for-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1277e89e");
  # https://support.microsoft.com/en-us/help/4341832/security-update-for-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b27d8590");
  # https://support.microsoft.com/en-us/help/4340937/security-update-for-the-microsoft-com-vulnerabilities-in-windows
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?03764b1c");
  # https://support.microsoft.com/en-us/help/4344104/security-update-for-font-library-vulnerability-in-windows
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8782f358");
  # https://support.microsoft.com/en-us/help/4343674/security-update-for-gdi-vulnerabilities-in-windows
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f77c369");
  # https://support.microsoft.com/en-us/help/4340939/security-update-for-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?09c0d01f");
  # https://blogs.technet.microsoft.com/srd/2018/08/10/analysis-and-mitigation-of-l1-terminal-fault-l1tf/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?818d7d6a");
  # https://support.microsoft.com/en-us/help/4072698/windows-server-speculative-execution-side-channel-vulnerabilities-prot
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8902cebb");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Windows Server 2008.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8344");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "microsoft_windows_env_vars.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("smb_reg_query.inc");
include("lists.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS18-08';

kbs = make_list(
  '4338380',
  '4340937',
  '4340939',
  '4341832',
  '4343674',
  '4344104'
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


# KB4338380
files = list_dir(basedir:winsxs, level:0, dir_pat:"offlinefiles-core_31bf3856ad364e35", file_pat:"^csc\.sys$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24436'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4338380", session:the_session);

# KB4340937
files = list_dir(basedir:winsxs, level:0, dir_pat:"installer-engine_31bf3856ad364e35", file_pat:"^msi\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('4.5.6002.24433'),
                            max_versions:make_list('4.5.6002.99999'),
                            bulletin:bulletin,
                            kb:"4340937", session:the_session);

# KB4340939
files = list_dir(basedir:winsxs, level:0, dir_pat:"structuredquery_31bf3856ad364e35", file_pat:"^msshsq\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('7.0.6002.24434'),
                            max_versions:make_list('7.0.6002.99999'),
                            bulletin:bulletin,
                            kb:"4340939", session:the_session);

# KB4341832
files = list_dir(basedir:winsxs, level:0, dir_pat:"os-kernel_31bf3856ad364e35", file_pat:"^ntoskrnl\.exe$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24444'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4341832", session:the_session);

# KB4343674
files = list_dir(basedir:winsxs, level:0, dir_pat:"gdi-painting_31bf3856ad364e35", file_pat:"^msimg32\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24439'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4343674", session:the_session);

# KB4344104
files = list_dir(basedir:winsxs, level:0, dir_pat:"-gdi_31bf3856ad364e35", file_pat:"^dciman32\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24441'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4344104", session:the_session);

hotfix_check_fversion_end();
NetUseDel();

if (vuln > 0)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else
{
  audit(AUDIT_HOST_NOT, 'affected');
}
