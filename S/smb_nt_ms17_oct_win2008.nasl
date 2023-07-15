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
  script_id(103816);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/04");

  script_cve_id(
    "CVE-2017-0250",
    "CVE-2017-8689",
    "CVE-2017-8694",
    "CVE-2017-8717",
    "CVE-2017-8718",
    "CVE-2017-11762",
    "CVE-2017-11763",
    "CVE-2017-11765",
    "CVE-2017-11771",
    "CVE-2017-11772",
    "CVE-2017-11780",
    "CVE-2017-11781",
    "CVE-2017-11784",
    "CVE-2017-11785",
    "CVE-2017-11790",
    "CVE-2017-11793",
    "CVE-2017-11810",
    "CVE-2017-11814",
    "CVE-2017-11815",
    "CVE-2017-11816",
    "CVE-2017-11817",
    "CVE-2017-11822",
    "CVE-2017-11824",
    "CVE-2017-13080"
  );
  script_bugtraq_id(
    98100,
    101077,
    101081,
    101093,
    101094,
    101095,
    101099,
    101100,
    101108,
    101109,
    101110,
    101111,
    101114,
    101116,
    101122,
    101128,
    101136,
    101140,
    101141,
    101147,
    101149,
    101161,
    101162,
    101274
  );
  script_xref(name:"MSKB", value:"4042050");
  script_xref(name:"MSFT", value:"MS17-4042050");
  script_xref(name:"MSKB", value:"4041671");
  script_xref(name:"IAVA", value:"2017-A-0310");
  script_xref(name:"MSFT", value:"MS17-4041671");
  script_xref(name:"MSKB", value:"4041944");
  script_xref(name:"MSFT", value:"MS17-4041944");
  script_xref(name:"MSKB", value:"4041995");
  script_xref(name:"MSFT", value:"MS17-4041995");
  script_xref(name:"MSKB", value:"4050795");
  script_xref(name:"MSFT", value:"MS17-4050795");
  script_xref(name:"MSKB", value:"4042067");
  script_xref(name:"MSFT", value:"MS17-4042067");
  script_xref(name:"MSKB", value:"4042120");
  script_xref(name:"MSFT", value:"MS17-4042120");
  script_xref(name:"MSKB", value:"4042121");
  script_xref(name:"MSFT", value:"MS17-4042121");
  script_xref(name:"MSKB", value:"4042122");
  script_xref(name:"MSFT", value:"MS17-4042122");

  script_name(english:"Windows 2008 October 2017 Multiple Security Updates (KRACK)");
  script_summary(english:"Checks the existence of Windows Server 2008 October 2017 Patches.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing multiple security updates released
on 2017/10/10. It is, therefore, affected by multiple
vulnerabilities :

- A buffer overflow vulnerability exists in the Microsoft JET
    Database Engine that could allow remote code execution on an
    affected system. An attacker who successfully exploited this
    vulnerability could take complete control of an affected system.
    (CVE-2017-0250)

  - A remote code execution vulnerability exists when
    Windows Search handles objects in memory. An attacker
    who successfully exploited this vulnerability could take
    control of the affected system. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights.
    (CVE-2017-11771)

  - An elevation of privilege vulnerability exists when the
    Windows Graphics Component improperly handles objects in
    memory. An attacker who successfully exploited this
    vulnerability could run processes in an elevated
    context.  (CVE-2017-11824)

  - An elevation of privilege vulnerability exists when the
    Windows kernel-mode driver fails to properly handle
    objects in memory. An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    kernel mode. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights.  (CVE-2017-8689, CVE-2017-8694)

  - A buffer overflow vulnerability exists in the Microsoft
    JET Database Engine that could allow remote code
    execution on an affected system. An attacker who
    successfully exploited this vulnerability could take
    control of an affected system. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights. Users whose
    accounts are configured to have fewer user rights on the
    system could be less impacted than users who operate
    with administrative user rights.  (CVE-2017-8717,
    CVE-2017-8718)

  - An information disclosure vulnerability exists in the
    way that the Windows Graphics Device Interface (GDI)
    handles objects in memory, allowing an attacker to
    retrieve information from a targeted system. By itself,
    the information disclosure does not allow arbitrary code
    execution; however, it could allow arbitrary code to be
    run if the attacker uses it in combination with another
    vulnerability.  (CVE-2017-11816)

  - An information disclosure vulnerability exists in the
    way that the Windows SMB Server handles certain
    requests. An authenticated attacker who successfully
    exploited this vulnerability could craft a special
    packet, which could lead to information disclosure from
    the server.  (CVE-2017-11815)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2017-11765, CVE-2017-11814)

  - A remote code execution vulnerability exists in the way
    that the scripting engine handles objects in memory in
    Internet Explorer. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2017-11793, CVE-2017-11810)

  - A remote code execution vulnerability exists when the
    Windows font library improperly handles specially
    crafted embedded fonts. An attacker who successfully
    exploited the vulnerability could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.  (CVE-2017-11762,
    CVE-2017-11763)

  - An information disclosure vulnerability exists when
    Internet Explorer improperly handles objects in memory.
    An attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2017-11790)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly initializes objects in memory.
    (CVE-2017-11817)

  - A denial of service vulnerability exists in the
    Microsoft Server Block Message (SMB) when an attacker
    sends specially crafted requests to the server. An
    attacker who exploited this vulnerability could cause
    the affected system to crash. To attempt to exploit this
    issue, an attacker would need to send specially crafted
    SMB requests to the target system. Note that the denial
    of service vulnerability would not allow an attacker to
    execute code or to elevate their user rights, but it
    could cause the affected system to stop accepting
    requests. The security update addresses the
    vulnerability by correcting the manner in which SMB
    handles specially crafted client requests.
    (CVE-2017-11781)

  - A remote code execution vulnerability exists when
    Internet Explorer improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2017-11822)

  - An Information disclosure vulnerability exists when
    Windows Search improperly handles objects in memory. An
    attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2017-11772)

  - A remote code execution vulnerability exists in the way
    that the Microsoft Server Message Block 1.0 (SMBv1)
    server handles certain requests. An attacker who
    successfully exploited the vulnerability could gain the
    ability to execute code on the target server.
    (CVE-2017-11780)

  - An information disclosure vulnerability exists in the
    Windows kernel that could allow an attacker to retrieve
    information that could lead to a Kernel Address Space
    Layout Randomization (ASLR) bypass. An attacker who
    successfully exploited the vulnerability could retrieve
    the memory address of a kernel object.  (CVE-2017-11784,
    CVE-2017-11785)

  - A spoofing vulnerability exists in the Windows
    implementation of wireless networking. An attacker who
    successfully exploited this vulnerability could
    potentially replay broadcast and/or multicast traffic
    to hosts on a WPA or WPA 2-protected wireless network.
    (CVE-2017-13080)");
  # https://support.microsoft.com/en-us/help/4042050/security-update-for-the-microsoft-jet-database-engine-remote-code-exec
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?47cf0955");
  # https://support.microsoft.com/en-us/help/4050795/unexpected-error-from-external-database-driver-error-when-you-create-o
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ef65f13");
  # https://support.microsoft.com/en-us/help/4041995/security-update-for-the-windows-smb-vulnerabilities-in-windows-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cdb3c598");
  # https://support.microsoft.com/en-us/help/4042067/security-update-for-search-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?492474c1");
  # https://support.microsoft.com/en-us/help/4041671/security-update-for-the-windows-kernel-information-disclosure-vulnerab
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?11033575");
  # https://support.microsoft.com/en-us/help/4042122/security-update-for-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?41b63a5b");
  # https://support.microsoft.com/en-us/help/4042120/security-update-for-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e644606");
  # https://support.microsoft.com/en-us/help/4042121/security-update-for-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?53858948");
  # https://support.microsoft.com/en-us/help/4040685/cumulative-security-update-for-internet-explorer
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86f61c93");
  # https://support.microsoft.com/en-us/help/4041944/windows-information-disclosure-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e2287b5e");
  script_set_attribute(attribute:"solution", value:
"Apply the following security updates :

  - 4041671
  - 4041944
  - 4041995
  - 4050795
  - 4042067
  - 4042120
  - 4042121
  - 4042122
  - 4042050");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11771");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

bulletin = 'MS17-10';

kbs = make_list(
  "4032201",
  "4034786",
  "4038874",
  "4039038",
  "4039266",
  "4039325",
  "4039384"
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

# 4041671
files = list_dir(basedir:winsxs, level:0, dir_pat:"os-kernel_31bf3856ad364e35", file_pat:"^ntoskrnl\.exe$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24202'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4041671", session:the_session);

# 4041944
files = list_dir(basedir:winsxs, level:0, dir_pat:"ntfs_31bf3856ad364e35", file_pat:"^ntfs\.sys$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24201'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4041944", session:the_session);

# 4041995
files = list_dir(basedir:winsxs, level:0, dir_pat:"smbserver-common_31bf3856ad364e35", file_pat:"^srvnet\.sys$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24201'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4041995", session:the_session);

# 4042067
files = list_dir(basedir:winsxs, level:0, dir_pat:"c..ent-indexing-common_31bf3856ad364e35", file_pat:"^query\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24201'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4042067", session:the_session);

# 4042120
files = list_dir(basedir:winsxs, level:0, dir_pat:"win32k_31bf3856ad364e35", file_pat:"^win32k\.sys$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24200'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4042120", session:the_session);

# 4042121
files = list_dir(basedir:winsxs, level:0, dir_pat:"gdi32_31bf3856ad364e35", file_pat:"^gdi32\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24200'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4042121", session:the_session);

# 4050795 (fix for 4042007)
files = list_dir(basedir:winsxs, level:0, dir_pat:"m..components-jetexcel_31bf3856ad364e35", file_pat:"^msexcl40\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('4.0.9801.2'),
                            max_versions:make_list('4.0.9801.9999'),
                            bulletin:bulletin,
                            kb:"4050795", session:the_session);

# 4042122
files = list_dir(basedir:winsxs, level:0, dir_pat:"font-embedding_31bf3856ad364e35", file_pat:"^t2embed\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24200'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4042122", session:the_session);

# 4042050
files = list_dir(basedir:winsxs, level:0, dir_pat:"mponents-jetintlerr_31bf3856ad364e35", file_pat:"^msjint40\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('4.0.9801.1'),
                            max_versions:make_list('4.0.9801.9999'),
                            bulletin:bulletin,
                            kb:"4042050", session:the_session);

# The following two checks are commented out
# due to released patches failing to apply
# to relavant systems.
## 4042123
#files = list_dir(basedir:winsxs, level:0, dir_pat:"t..icesframework-msctf_31bf3856ad364e35", file_pat:"^msctf\.dll$", max_recurse:1);
#vuln += hotfix_check_winsxs(os:'6.0',
#                            sp:2,
#                            files:files,
#                            versions:make_list('6.0.6002.16386', '6.0.6002.24202'),
#                            max_versions:make_list('6.0.6002.20000', '6.0.6003.99999'),
#                            bulletin:bulletin,
#                            kb:"4042123", session:the_session);
#
## 4042723
#files = list_dir(basedir:winsxs, level:0, dir_pat:"wlansvc_31bf3856ad364e35", file_pat:"^wlanapi\.dll$", max_recurse:1);
#vuln += hotfix_check_winsxs(os:'6.0',
#                            sp:2,
#                            files:files,
#                            versions:make_list('6.0.6001.18000', '6.0.6002.24202'),
#                            max_versions:make_list('6.0.6001.20000', '6.0.6003.99999'),
#                            bulletin:bulletin,
#                            kb:"4042723", session:the_session);

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
