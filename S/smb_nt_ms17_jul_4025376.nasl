#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101370);
  script_version("1.14");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-3080", "CVE-2017-3099", "CVE-2017-3100");
  script_bugtraq_id(99519, 99520, 99523);
  script_xref(name:"MSKB", value:"4025376");
  script_xref(name:"MSFT", value:"MS17-4025376");

  script_name(english:"KB4025376: Security update for Adobe Flash Player (July 2017)");
  script_summary(english:"Checks the version of the ActiveX control.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update KB4025376. It is,
therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists due to an
    unspecified flaw. An unauthenticated, remote attacker
    can exploit this, by convincing a user to visit a
    website containing specially crafted Flash content, to
    disclose sensitive information. (CVE-2017-3080)

  - A remote code execution vulnerability exists due to
    improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to visit a website containing
    specially crafted Flash content, to execute arbitrary
    code. (CVE-2017-3099)

  - An information disclosure vulnerability exists that
    allows an unauthenticated, remote attacker to corrupt
    memory and disclose memory addresses. (CVE-2017-3100)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4025376/security-update-for-adobe-flash-player-july-11-2017");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb17-21.html");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2012, 8.1, RT 8.1,
2012 R2, 10, and 2016.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3099");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_activex_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS17-07';
kbs = make_list("4025376");

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "Windows 8.1" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

if (activex_init() != ACX_OK) audit(AUDIT_FN_FAIL, "activex_init()");

# Adobe Flash Player CLSID
clsid = '{D27CDB6E-AE6D-11cf-96B8-444553540000}';

file = activex_get_filename(clsid:clsid);
if (isnull(file))
{
  activex_end();
  audit(AUDIT_FN_FAIL, "activex_get_filename", "NULL");
}
if (!file)
{
  activex_end();
  audit(AUDIT_ACTIVEX_NOT_FOUND, clsid);
}

# Get its version.
version = activex_get_fileversion(clsid:clsid);
if (!version)
{
  activex_end();
  audit(AUDIT_VER_FAIL, file);
}

info = '';

iver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(iver); i++)
 iver[i] = int(iver[i]);
iver = join(iver, sep:".");

# all <= 26.0.0.120
fix = FALSE;
if (ver_compare(ver:iver, fix:"26.0.0.120", strict:FALSE) <= 0)
  fix = "26.0.0.137";

if (
  (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0) &&
  fix
)
{
  info = '\n  Path              : ' + file +
         '\n  Installed version : ' + version +
         '\n  Fixed version     : ' + fix +
         '\n';
}

port = kb_smb_transport();

if (info != '')
{
  if (report_paranoia > 1)
  {
    report = info +
      '\n' +
      'Note, though, that Nessus did not check whether the kill bit was\n' +
      "set for the control's CLSID because of the Report Paranoia setting" + '\n' +
      'in effect when this scan was run.\n';
  }
  else
  {
    report = info +
      '\n' +
      'Moreover, its kill bit is not set so it is accessible via Internet\n' +
      'Explorer.\n';
  }
  replace_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_add_report(bulletin:'MS17-07', kb:'4025376', report);
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:hotfix_get_report());
}
else audit(AUDIT_HOST_NOT, 'affected');
