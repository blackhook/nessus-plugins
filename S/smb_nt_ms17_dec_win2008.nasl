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
  script_id(105191);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/04");

  script_cve_id("CVE-2017-11768", "CVE-2017-11885", "CVE-2017-11927");
  script_bugtraq_id(101705, 102055, 102095);
  script_xref(name:"MSKB", value:"4047170");
  script_xref(name:"MSFT", value:"MS17-4047170");
  script_xref(name:"MSKB", value:"4052303");
  script_xref(name:"MSFT", value:"MS17-4052303");
  script_xref(name:"MSKB", value:"4053473");
  script_xref(name:"MSFT", value:"MS17-4053473");

  script_name(english:"Windows 2008 December 2017 Multiple Security Updates");
  script_summary(english:"Checks the existence of Windows Server 2008 December 2017 Patches.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing multiple security updates released
on 2017/12/12. It is, therefore, affected by multiple
vulnerabilities :

- An information vulnerability exists when Windows Media
    Player improperly discloses file information. Successful
    exploitation of the vulnerability could allow the
    attacker to test for the presence of files on disk.
    (CVE-2017-11768)

  - A remote code execution vulnerability exists in RPC if
    the server has Routing and Remote Access enabled. An
    attacker who successfully exploited this vulnerability
    could execute code on the target system. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    (CVE-2017-11885)
  
  - An information disclosure vulnerability exists when the
    Windows its:// protocol handler unnecessarily sends
    traffic to a remote site in order to determine the zone
    of a provided URL. This could potentially result in the
    disclosure of sensitive information to a malicious site.
    (CVE-2017-11927)");
  # https://support.microsoft.com/en-us/help/4047170/security-update-for-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b4fb53fa");
  # https://support.microsoft.com/en-us/help/4052303/security-update-for-vulnerabilities-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6218937f");
  # https://support.microsoft.com/en-us/help/4053473/security-update-for-the-information-disclosure-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fae1fdfc");
  script_set_attribute(attribute:"solution", value:
"Apply the following security updates :
  - 4047170
  - 4052303
  - 4053473");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11885");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/12");

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

bulletin = 'MS17-12';

kbs = make_list(
  "4047170",
  "4052303",
  "4053473"
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

# 4052303
files = list_dir(basedir:winsxs, level:0, dir_pat:"rasserver_31bf3856ad364e35", file_pat:"^iprtprio\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24231'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4052303", session:the_session);

# 4053473
files = list_dir(basedir:winsxs, level:0, dir_pat:"htmlhelp-infotech_31bf3856ad364e35", file_pat:"^itircl\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.24233'),
                            max_versions:make_list('6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4053473", session:the_session);

# 4047170
if(hotfix_is_vulnerable(os:"6.0", sp:2, file:"wmp.dll", version:"11.0.6002.24234", min_version:"11.0.6002.16000", dir:"\system32", bulletin:bulletin, kb:"4047170"))
  vuln++;

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
