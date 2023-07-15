#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(100788);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id(
    "CVE-2017-0222",
    "CVE-2017-0267",
    "CVE-2017-8464",
    "CVE-2017-8487",
    "CVE-2017-8543"
  );
  script_bugtraq_id(
    98127,
    98259,
    98818,
    98824,
    99013
  );
  script_xref(name:"MSKB", value:"4022839");
  script_xref(name:"MSKB", value:"4019623");
  script_xref(name:"MSKB", value:"4018271");
  script_xref(name:"MSFT", value:"MS17-4022839");
  script_xref(name:"MSFT", value:"MS17-4019623");
  script_xref(name:"MSFT", value:"MS17-4018271");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/08/10");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/08/25");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/14");

  script_name(english:"Windows 8 June 2017 Security Updates");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows 8 host is missing a security update. It is,
therefore, affected by the following vulnerabilities :

  - A remote code execution vulnerability exists in
    Microsoft Internet Explorer due to improper handling of
    objects in memory. An unauthenticated, remote attacker
    can exploit this, by convincing a user to visit a
    specially crafted website, to execute arbitrary code in
    the context of the current user. (CVE-2017-0222)

  - An information disclosure vulnerability exists in the
    Microsoft Server Message Block 1.0 (SMBv1) server when
    handling certain requests. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    packet, to disclose sensitive information.
    (CVE-2017-0267)

  - A remote code execution vulnerability exists in Windows
    due to improper handling of shortcuts. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to insert a removable drive containing
    a malicious shortcut and binary, to automatically
    execute arbitrary code in the context of the current
    user. (CVE-2017-8464)

  - A remote code execution vulnerability exists in Windows
    OLE due to improper validation of user-supplied input.
    An unauthenticated, remote attacker can exploit this, by
    convincing a user to visit a specially crafted website or
    to open a specially crafted file or email message, to
    execute arbitrary code in the context of the current
    user. (CVE-2017-8487)

  - A remote code execution vulnerability exists in the
    Windows Search functionality due to improper handling of
    objects in memory. An unauthenticated, remote attacker
    can exploit this, via a specially crafted SMB message,
    to execute arbitrary code. (CVE-2017-8543)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4012598/title");
  # https://support.microsoft.com/en-us/help/4012583/ms17-011-and-ms17-013-description-of-the-security-update-for-microsoft
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba79a274");
  # https://support.microsoft.com/en-ca/help/4022839/description-of-the-security-update-for-windows-8-june-13-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d15161da");
  # http://www.catalog.update.microsoft.com/Search.aspx?q=KB4019623
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00067ec3");
  # https://support.microsoft.com/en-us/help/4018271/cumulative-security-update-for-internet-explorer-may-9-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5470f743");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released emergency patches for Windows 8. Apply security
updates KB4022839, KB4019623, and KB4018271");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8543");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'LNK Code Execution Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2022 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "smb_check_rollup.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS17-06';
kbs = make_list(
  "4022839",
  "4019623",
  "4018271"
);

vuln = 0;

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win8:'0') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Server" >< productname)
  audit(AUDIT_OS_NOT, "Windows 8");

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share))
  audit(AUDIT_SHARE_FAIL, share);

if (
  # 4022839
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"shell32.dll", version:"6.2.9200.22164", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"4022839")
  ||
  # 4019623
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"srv.sys", version:"6.2.9200.22137", min_version:"6.2.9200.16000", dir:"\system32\drivers", bulletin:bulletin, kb:"4019623")
  ||
  # 4018271
  # x86
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"hlink.dll", version:"6.0.6002.22092", min_version:"6.0.6002.16000", dir:"\system32", bulletin:bulletin, kb:"4018271")
  ||
  # x64
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"hlink.dll", version:"6.0.6002.22104", min_version:"6.0.6002.16000", dir:"\system32", bulletin:bulletin, kb:"4018271")

)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}
