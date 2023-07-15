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
  script_id(106818);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/04");

  script_cve_id(
    "CVE-2018-0742",
    "CVE-2018-0757",
    "CVE-2018-0810",
    "CVE-2018-0820",
    "CVE-2018-0825",
    "CVE-2018-0829",
    "CVE-2018-0830",
    "CVE-2018-0842",
    "CVE-2018-0844",
    "CVE-2018-0846",
    "CVE-2018-0847"
  );
  script_bugtraq_id(
    102861,
    102920,
    102929,
    102931,
    102937,
    102938,
    102945,
    102946,
    102947,
    102948,
    102949
  );
  script_xref(name:"MSKB", value:"4058165");
  script_xref(name:"MSKB", value:"4073080");
  script_xref(name:"MSKB", value:"4034044");
  script_xref(name:"MSKB", value:"4073079");
  script_xref(name:"MSKB", value:"4074851");
  script_xref(name:"MSKB", value:"4074836");
  script_xref(name:"MSKB", value:"4074603");
  script_xref(name:"MSFT", value:"MS18-4058165");
  script_xref(name:"MSFT", value:"MS18-4073080");
  script_xref(name:"MSFT", value:"MS18-4034044");
  script_xref(name:"MSFT", value:"MS18-4073079");
  script_xref(name:"MSFT", value:"MS18-4074851");
  script_xref(name:"MSFT", value:"MS18-4074836");
  script_xref(name:"MSFT", value:"MS18-4074603");

  script_name(english:"Security Updates for Windows Server 2008 (February 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security updates. It is,
therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists when the
    Windows kernel improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2018-0757, CVE-2018-0829, CVE-2018-0830)

  - An information disclosure vulnerability exists when
    VBScript improperly discloses the contents of its
    memory, which could provide an attacker with information
    to further compromise the users computer or data.
    (CVE-2018-0847)

  - A remote code execution vulnerability exists in
    StructuredQuery when the software fails to properly
    handle objects in memory. An attacker who successfully
    exploited the vulnerability could run arbitrary code in
    the context of the current user. If the current user is
    logged on with administrative user rights, an attacker
    could take control of the affected system. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    (CVE-2018-0825)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Kernel handles objects in memory.
    An attacker who successfully exploited the vulnerability
    could execute code with elevated permissions.
    (CVE-2018-0742, CVE-2018-0820)

  - A remote code execution vulnerability exists when
    Windows improperly handles objects in memory. An
    attacker who successfully exploited these
    vulnerabilities could take control of an affected
    system.  (CVE-2018-0842)

  - An elevation of privilege vulnerability exists when the
    Windows Common Log File System (CLFS) driver improperly
    handles objects in memory. An attacker who successfully
    exploited this vulnerability could run processes in an
    elevated context.  (CVE-2018-0844, CVE-2018-0846)

  - An information disclosure vulnerability exists when the
    Windows kernel fails to properly initialize a memory
    address. An attacker who successfully exploited this
    vulnerability could obtain information to further
    compromise the users system.  (CVE-2018-0810)");
  # https://support.microsoft.com/en-us/help/4058165/security-update-for-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b4502bd9");
  # https://support.microsoft.com/en-us/help/4073080/security-update-for-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f1605c63");
  # https://support.microsoft.com/en-us/help/4034044/security-update-for-the-scripting-engine-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?859aacbd");
  # https://support.microsoft.com/en-us/help/4073079/security-update-for-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bcb52b2e");
  # https://support.microsoft.com/en-us/help/4074851/security-update-for-vulnerability-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?90a704be");
  # https://support.microsoft.com/en-us/help/4074836/security-update-for-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1ef076d3");
  # https://support.microsoft.com/en-us/help/4074603/security-update-for-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0bb99366");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4058165
  -KB4073080
  -KB4034044
  -KB4073079
  -KB4074851
  -KB4074836
  -KB4074603");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0825");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/14");

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

bulletin = 'MS18-02';

kbs = make_list(
  "4058165",
  "4073080",
  "4034044",
  "4073079",
  "4074851",
  "4074836",
  "4074603"
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

# KB4034044
files = list_dir(basedir:winsxs, level:0, dir_pat:"cdosys_31bf3856ad364e35", file_pat:"^cdosys\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.6.6002.24282'),
                            max_versions:make_list('6.6.6002.99999'),
                            bulletin:bulletin,
                            kb:"4034044", session:the_session);

# KB4058165
files = list_dir(basedir:winsxs, level:0, dir_pat:"tcpip-binaries_31bf3856ad364e35", file_pat:"^tcpip\.sys$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24296'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4058165", session:the_session);

# KB4073079
files = list_dir(basedir:winsxs, level:0, dir_pat:"commonlog_31bf3856ad364e35", file_pat:"^clfs\.sys$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24282'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4073079", session:the_session);

# KB4073080
files = list_dir(basedir:winsxs, level:0, dir_pat:"csrsrv_31bf3856ad364e35", file_pat:"^csrsrv\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24282'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4073080", session:the_session);

# KB4074603
files = list_dir(basedir:winsxs, level:0, dir_pat:"win32k_31bf3856ad364e35", file_pat:"^win32k\.sys$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24281'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4074603", session:the_session);

# KB4074836
files = list_dir(basedir:winsxs, level:0, dir_pat:"input.inf_31bf3856ad364e35", file_pat:"^hidir\.sys$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24282'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4074836", session:the_session);
# KB4074851
files = list_dir(basedir:winsxs, level:0, dir_pat:"-structuredquery_31bf3856ad364e35", file_pat:"^msshsq\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('7.0.6002.24282'),
                            max_versions:make_list('7.0.6002.99999'),
                            bulletin:bulletin,
                            kb:"4074851", session:the_session);

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
