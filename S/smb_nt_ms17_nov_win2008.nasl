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
  script_id(104561);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/04");

  script_cve_id(
    "CVE-2017-11788",
    "CVE-2017-11831",
    "CVE-2017-11832",
    "CVE-2017-11835",
    "CVE-2017-11847",
    "CVE-2017-11849",
    "CVE-2017-11851",
    "CVE-2017-11852",
    "CVE-2017-11853",
    "CVE-2017-11880"
  );
  script_bugtraq_id(
    101711,
    101721,
    101726,
    101729,
    101736,
    101739,
    101755,
    101762,
    101763,
    101764
  );
  script_xref(name:"MSKB", value:"4046184");
  script_xref(name:"MSFT", value:"MS17-4046184");
  script_xref(name:"MSKB", value:"4047211");
  script_xref(name:"MSFT", value:"MS17-4047211");
  script_xref(name:"MSKB", value:"4048968");
  script_xref(name:"MSFT", value:"MS17-4048968");
  script_xref(name:"MSKB", value:"4048970");
  script_xref(name:"MSFT", value:"MS17-4048970");
  script_xref(name:"MSKB", value:"4049164");
  script_xref(name:"MSFT", value:"MS17-4049164");

  script_name(english:"Windows 2008 November 2017 Multiple Security Updates");
  script_summary(english:"Checks the existence of Windows Server 2008 November 2017 Patches.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing multiple security updates released
on 2017/11/14. It is, therefore, affected by multiple
vulnerabilities :

  - An information disclosure vulnerability exists when the
    Windows kernel improperly initializes objects in memory.
    (CVE-2017-11880)
  
  - An information disclosure vulnerability exists in the
    way that the Microsoft Windows Embedded OpenType (EOT)
    font engine parses specially crafted embedded fonts. An
    attacker who successfully exploited this vulnerability
    could potentially read data that was not intended to be
    disclosed. Note that this vulnerability would not allow
    an attacker to execute code or to elevate their user
    rights directly, but it could be used to obtain
    information that could be used to try to further
    compromise the affected system.  (CVE-2017-11832,
    CVE-2017-11835)
  
  - An elevation of privilege vulnerability exists when the
    Windows kernel fails to properly handle objects in
    memory. An attacker who successfully exploited this
    vulnerability could run arbitrary code in kernel mode.
    An attacker could then install programs; view, change,
    or delete data; or create new accounts with full user
    rights.  (CVE-2017-11847)
  
  - An information disclosure vulnerability exists when the
    Windows kernel fails to properly initialize a memory
    address. An attacker who successfully exploited this
    vulnerability could obtain information to further
    compromise the users system.  (CVE-2017-11831,
    CVE-2017-11849, CVE-2017-11853)
  
  - A denial of service vulnerability exists when Windows
    Search improperly handles objects in memory. An attacker
    who successfully exploited the vulnerability could cause
    a remote denial of service against a system.
    (CVE-2017-11788)
  
  - A Win32k information disclosure vulnerability exists
    when the Windows GDI component improperly discloses
    kernel memory addresses. An attacker who successfully
    exploited the vulnerability could obtain information to
    further compromise the users system.  (CVE-2017-11851,
    CVE-2017-11852)");
  # https://support.microsoft.com/en-us/help/4046184/security-update-for-windows-information-disclosure
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?93affd27");
  # https://support.microsoft.com/en-us/help/4048968/windows-eot-font-engine-information-disclosure-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6ae2aa8e");
  # https://support.microsoft.com/en-us/help/4049164/security-update-for-information-disclosure-vulnerability-in-windows-se
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a4acc26");
  # https://support.microsoft.com/en-us/help/4048970/security-update-for-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2b1232ba");
  # https://support.microsoft.com/en-us/help/4047211/security-update-for-the-windows-search-denial-of-service-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fea3380b");
  script_set_attribute(attribute:"solution", value:
"Apply the following security updates :

  - 4046184
  - 4047211
  - 4048968
  - 4048970
  - 4049164");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11847");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = 'MS17-11';

kbs = make_list(
  "4046184",
  "4047211",
  "4048968",
  "4048970",
  "4049164"
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

# 4049164
files = list_dir(basedir:winsxs, level:0, dir_pat:"ntfs_31bf3856ad364e35", file_pat:"^ntfs\.sys$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24215'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4049164", session:the_session);

# 4047211
files = list_dir(basedir:winsxs, level:0, dir_pat:"c..ent-indexing-common_31bf3856ad364e35", file_pat:"^query\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24215'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4047211", session:the_session);

# 4048970
files = list_dir(basedir:winsxs, level:0, dir_pat:"win32k_31bf3856ad364e35", file_pat:"^win32k\.sys$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24215'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4048970", session:the_session);

# 4048968
files = list_dir(basedir:winsxs, level:0, dir_pat:"font-embedding_31bf3856ad364e35", file_pat:"^t2embed\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24215'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4048968", session:the_session);

# 4046184
files = list_dir(basedir:winsxs, level:0, dir_pat:"lua-filevirtualization_31bf3856ad364e35", file_pat:"^luafv\.sys$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24215'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4046184", session:the_session);

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
