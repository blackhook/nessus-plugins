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
  script_id(108975);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/04");

  script_cve_id(
    "CVE-2018-0887",
    "CVE-2018-0960",
    "CVE-2018-0967",
    "CVE-2018-0969",
    "CVE-2018-0970",
    "CVE-2018-0971",
    "CVE-2018-0972",
    "CVE-2018-0973",
    "CVE-2018-0974",
    "CVE-2018-0975",
    "CVE-2018-0976",
    "CVE-2018-1003",
    "CVE-2018-1008",
    "CVE-2018-1010",
    "CVE-2018-1012",
    "CVE-2018-1013",
    "CVE-2018-1015",
    "CVE-2018-1016",
    "CVE-2018-8116"
  );
  script_xref(name:"MSKB", value:"4093478");
  script_xref(name:"MSKB", value:"4093227");
  script_xref(name:"MSKB", value:"4093224");
  script_xref(name:"MSKB", value:"4093223");
  script_xref(name:"MSKB", value:"4093257");
  script_xref(name:"MSKB", value:"4091756");
  script_xref(name:"MSFT", value:"MS18-4093478");
  script_xref(name:"MSFT", value:"MS18-4093227");
  script_xref(name:"MSFT", value:"MS18-4093224");
  script_xref(name:"MSFT", value:"MS18-4093223");
  script_xref(name:"MSFT", value:"MS18-4093257");
  script_xref(name:"MSFT", value:"MS18-4091756");

  script_name(english:"Security Updates for Windows Server 2008 (April 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security updates. It is,
therefore, affected by multiple vulnerabilities :

  - An elevation of privilege vulnerability exists in
    Windows Adobe Type Manager Font Driver (ATMFD.dll) when
    it fails to properly handle objects in memory. An
    attacker who successfully exploited this vulnerability
    could execute arbitrary code and take control of an
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.  (CVE-2018-1008)

  - A buffer overflow vulnerability exists in the Microsoft
    JET Database Engine that could allow remote code
    execution on an affected system. An attacker who
    successfully exploited this vulnerability could take
    control of an affected system. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights. Users whose
    accounts are configured to have fewer user rights on the
    system could be less impacted than users who operate
    with administrative user rights.  (CVE-2018-1003)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2018-0960)

  - A denial of service vulnerability exists in the way that
    Windows handles objects in memory. An attacker who
    successfully exploited the vulnerability could cause a
    target system to stop responding. Note that the denial
    of service condition would not allow an attacker to
    execute code or to elevate user privileges. However, the
    denial of service condition could prevent authorized
    users from using system resources. The security update
    addresses the vulnerability by correcting how Windows
    handles objects in memory. (CVE-2018-8116)

  - A denial of service vulnerability exists in the way that
    Windows SNMP Service handles malformed SNMP traps. An
    attacker who successfully exploited the vulnerability
    could cause a target system to stop responding. Note
    that the denial of service condition would not allow an
    attacker to execute code or to elevate user privileges.
    However, the denial of service condition could prevent
    authorized users from using system resources. The
    security update addresses the vulnerability by
    correcting how Windows SNMP Service processes SNMP
    traps. (CVE-2018-0967)

  - A remote code execution vulnerability exists in the way
    that the VBScript engine handles objects in memory. The
    vulnerability could corrupt memory in such a way that an
    attacker could execute arbitrary code in the context of
    the current user. An attacker who successfully exploited
    the vulnerability could gain the same user rights as the
    current user.  (CVE-2018-1004)

  - An information disclosure vulnerability exists in the
    Windows kernel that could allow an attacker to retrieve
    information that could lead to a Kernel Address Space
    Layout Randomization (ASLR) bypass. An attacker who
    successfully exploited the vulnerability could retrieve
    the memory address of a kernel object.  (CVE-2018-0969,
    CVE-2018-0970, CVE-2018-0971, CVE-2018-0972,
    CVE-2018-0973, CVE-2018-0974, CVE-2018-0975)

  - A denial of service vulnerability exists in Remote
    Desktop Protocol (RDP) when an attacker connects to the
    target system using RDP and sends specially crafted
    requests. An attacker who successfully exploited this
    vulnerability could cause the RDP service on the target
    system to stop responding.  (CVE-2018-0976)

  - A remote code execution vulnerability exists when the
    Windows font library improperly handles specially
    crafted embedded fonts. An attacker who successfully
    exploited the vulnerability could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.  (CVE-2018-1010,
    CVE-2018-1012, CVE-2018-1013, CVE-2018-1015,
    CVE-2018-1016)

  - An information disclosure vulnerability exists when the
    Windows kernel fails to properly initialize a memory
    address. An attacker who successfully exploited this
    vulnerability could obtain information to further
    compromise the users system.  (CVE-2018-0887)");
  # https://support.microsoft.com/en-us/help/4093478/security-update-for-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eec22067");
  # https://support.microsoft.com/en-us/help/4093227/security-update-for-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d3bb84fc");
  # https://support.microsoft.com/en-us/help/4093224/security-update-for-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c1dd4c1c");
  # https://support.microsoft.com/en-us/help/4093223/security-update-for-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c271e994");
  # https://support.microsoft.com/en-us/help/4093257/security-update-for-vulnerabilities-in-windows-server-2008-and-windows
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?33481565");
  # https://support.microsoft.com/en-us/help/4091756/security-update-for-vulnerabilities-in-windows-server-2008-and-windows
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0058adf3");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4093478
  -KB4093227
  -KB4093224
  -KB4093223
  -KB4093257
  -KB4091756");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1016");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/10");

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

bulletin = 'MS18-04';

kbs = make_list(
  "4091756",
  "4093223",
  "4093224",
  "4093227",
  "4093257",
  "4093478"
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

# KB4091756
files = list_dir(basedir:winsxs, level:0, dir_pat:"snmp-winsnmp-api_31bf3856ad364e35", file_pat:"^wsnmp32\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24329'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4091756", session:the_session);

# KB4093223
files = list_dir(basedir:winsxs, level:0, dir_pat:"font-embedding_31bf3856ad364e35", file_pat:"^t2embed\.dll$", max_recurse:1);
vuln +=  hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24311'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4093223", session:the_session);

# KB4093224
files = list_dir(basedir:winsxs, level:0, dir_pat:"win32k_31bf3856ad364e35", file_pat:"^win32k\.sys$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24344'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4093224", session:the_session);

# KB4093227
files = list_dir(basedir:winsxs, level:0, dir_pat:"smartcardksp_31bf3856ad364e35", file_pat:"^scksp\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24329'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4093227", session:the_session);

# KB4093257
files = list_dir(basedir:winsxs, level:0, dir_pat:"components-jetexcel_31bf3856ad364e35", file_pat:"^msexcl40\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('4.0.9801.3'),
                            max_versions:make_list('4.0.9801.99999'),
                            bulletin:bulletin,
                            kb:"4093257", session:the_session);

# KB4093478
files = list_dir(basedir:winsxs, level:0, dir_pat:"blackbox-driver_31bf3856ad364e35", file_pat:"^spsys\.sys$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24298'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4093478", session:the_session);

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
