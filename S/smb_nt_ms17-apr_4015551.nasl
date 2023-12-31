#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(99285);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id(
    "CVE-2013-6629",
    "CVE-2017-0042",
    "CVE-2017-0158",
    "CVE-2017-0163",
    "CVE-2017-0166",
    "CVE-2017-0168",
    "CVE-2017-0169",
    "CVE-2017-0180",
    "CVE-2017-0182",
    "CVE-2017-0183",
    "CVE-2017-0184",
    "CVE-2017-0185",
    "CVE-2017-0186",
    "CVE-2017-0188",
    "CVE-2017-0191",
    "CVE-2017-0192",
    "CVE-2017-0199",
    "CVE-2017-0201",
    "CVE-2017-0210",
    "CVE-2017-0211"
  );
  script_bugtraq_id(
    63676,
    96098,
    97418,
    97427,
    97428,
    97435,
    97437,
    97438,
    97444,
    97446,
    97452,
    97454,
    97455,
    97459,
    97465,
    97466,
    97475,
    97498,
    97512,
    97514
  );
  script_xref(name:"CERT", value:"921560");
  script_xref(name:"EDB-ID", value:"41894");
  script_xref(name:"EDB-ID", value:"41934");
  script_xref(name:"MSKB", value:"4015548");
  script_xref(name:"MSKB", value:"4015551");
  script_xref(name:"MSFT", value:"MS17-4015548");
  script_xref(name:"MSFT", value:"MS17-4015551");
  script_xref(name:"IAVA", value:"2017-A-0110");
  script_xref(name:"IAVA", value:"2017-A-0111");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/14");

  script_name(english:"Windows Server 2012 April 2017 Security Updates (Petya)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4015548
or cumulative update 4015551. It is, therefore, affected by
multiple vulnerabilities :

  - An information disclosure vulnerability exists in the
    open-source libjpeg image processing library due to
    improper handling of objects in memory. An
    unauthenticated, remote attacker can exploit this to
    disclose sensitive information that can be utilized to
    bypass ASLR security protections. (CVE-2013-6629)

  - An information disclosure vulnerability exists in
    Windows DirectShow due to improper handling of objects
    in memory. Any unauthenticated, remote attacker can
    exploit this, by convincing a user to visit a website
    with specially crafted media content, to disclose
    sensitive information. (CVE-2017-0042)

  - Multiple information disclosure vulnerabilities exist in
    the win32k component due to improper handling of kernel
    information. A local attacker can exploit these
    vulnerabilities, via a specially crafted application, to
    disclose sensitive information. (CVE-2017-0058,
    CVE-2017-0188)

  - Multiple flaws exist in Windows Hyper-V Network Switch
    due to improper validation of input from the guest
    operating system. A local attacker can exploit these,
    via a specially crafted application on the guest, to
    execute arbitrary code on the host system.
    (CVE-2017-0163, CVE-2017-0180)

  - A flaw exists in LDAP due to buffer request lengths not
    being properly calculated. An unauthenticated, remote
    attacker can exploit this, via specially crafted traffic
    sent to a Domain Controller, to run processes with
    elevated privileges. (CVE-2017-0166)

  - Multiple information disclosure vulnerabilities exist in
    Windows Hyper-V Network Switch due to improper validation
    of user-supplied input. A guest attacker can exploit
    these to disclose sensitive information on the host
    server. (CVE-2017-0168, CVE-2017-0169)

  - Multiple denial of service vulnerabilities exist in
    Windows Hyper-V Network Switch due to improper
    validation of input from the guest operating system. A
    local attacker on the guest can exploit these
    vulnerabilities, via a specially crafted application, to
    crash the host system. (CVE-2017-0182, CVE-2017-0183,
    CVE-2017-0185, CVE-2017-0186)

  - Multiple denial of service vulnerabilities exist in
    Hyper-V due to improper validation of input from a
    privileged user on a guest operating system. A local
    attacker on the guest can exploit these, via a specially
    crafted application, to cause the host system to crash.
    (CVE-2017-0184)

  - A flaw exists in Windows due to improper handling of
    objects in memory that allows an attacker to cause a
    denial of service condition. (CVE-2017-0191)

  - An information disclosure vulnerability exists in the
    Adobe Type Manager Font Driver (ATMFD.dll) due to
    improper handling of objects in memory. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to open a specially crafted document
    or visit a malicious web page, to disclose sensitive
    information. (CVE-2017-0192)

  - An arbitrary code execution vulnerability exists in
    Microsoft Office and Windows WordPad due to improper
    handling of specially crafted files. An unauthenticated,
    remote attacker can exploit this, by convincing a user
    to open a malicious file, to execute arbitrary code in
    the context of the current user. Note that this
    vulnerability is being utilized to spread the Petya
    ransomware. (CVE-2017-0199)

  - A memory corruption issue exists in Internet
    Explorer in the JScript and VBScript engines due to
    improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to visit a malicious website, to
    execute arbitrary code. (CVE-2017-0201)

  - A privilege escalation vulnerability exists in Internet
    Explorer due to a failure to properly enforce
    cross-domain policies. An unauthenticated, remote
    attacker can exploit this to inject arbitrary content
    and gain elevated privileges. (CVE-2017-0210)

  - A privilege escalation vulnerability exists in Microsoft
    Windows OLE due to an unspecified failure in
    integrity-level checks. An authenticated, remote
    attacker can exploit this to run an application with
    limited privileges at a medium integrity level. Note
    that this vulnerability by itself does not allow
    arbitrary code execution but can be used in conjunction
    other vulnerabilities. (CVE-2017-0211)");
  # https://support.microsoft.com/en-us/help/4015551/windows-server-2012-update-kb4015551
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?782139c0");
  # https://www.tenable.com/blog/petyanotpetya-ransomware-detection-for-the-modern-enterprise
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59db5b5b");
  script_set_attribute(attribute:"solution", value:
"Apply Security Only update KB4015548 or Cumulative update KB4015551.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-0199");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-0166");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Office Word Malicious Hta Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "smb_check_rollup.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS17-04';
kbs = make_list(
  '4015548', # 2012 Security Only
  '4015551'  # 2012 Monthly Rollup
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# Windows 8 EOL
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if ( smb_check_rollup(os:"6.2", sp:0, rollup_date: "04_2017", bulletin:bulletin, rollup_kb_list:[4015548, 4015551]) )
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}
