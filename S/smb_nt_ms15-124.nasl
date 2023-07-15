#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87253);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/02");

  script_cve_id(
    "CVE-2015-6083",
    "CVE-2015-6134",
    "CVE-2015-6135",
    "CVE-2015-6136",
    "CVE-2015-6138",
    "CVE-2015-6139",
    "CVE-2015-6140",
    "CVE-2015-6141",
    "CVE-2015-6142",
    "CVE-2015-6143",
    "CVE-2015-6144",
    "CVE-2015-6145",
    "CVE-2015-6146",
    "CVE-2015-6147",
    "CVE-2015-6148",
    "CVE-2015-6149",
    "CVE-2015-6150",
    "CVE-2015-6151",
    "CVE-2015-6152",
    "CVE-2015-6153",
    "CVE-2015-6154",
    "CVE-2015-6155",
    "CVE-2015-6156",
    "CVE-2015-6157",
    "CVE-2015-6158",
    "CVE-2015-6159",
    "CVE-2015-6160",
    "CVE-2015-6161",
    "CVE-2015-6162",
    "CVE-2015-6164"
  );
  script_bugtraq_id(
    78481,
    78482,
    78483,
    78484,
    78485,
    78486,
    78487,
    78488,
    78489,
    78490,
    78491,
    78492,
    78494,
    78495,
    78507,
    78508,
    78526,
    78527,
    78528,
    78529,
    78530,
    78531,
    78532,
    78533,
    78534,
    78535,
    78536,
    78537,
    78538,
    78540
  );
  script_xref(name:"MSFT", value:"MS15-124");
  script_xref(name:"MSKB", value:"3104002");
  script_xref(name:"MSKB", value:"3116869");
  script_xref(name:"MSKB", value:"3116900");
  script_xref(name:"MSKB", value:"3125869");

  script_name(english:"MS15-124: Cumulative Security Update for Internet Explorer (3116180)");
  script_summary(english:"Checks the version of mshtml.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Internet Explorer installed on the remote host is
missing Cumulative Security Update 3116180. It is, therefore, affected
by multiple vulnerabilities, the majority of which are remote code
execution vulnerabilities. An unauthenticated, remote attacker can
exploit these issues by convincing a user to visit a specially crafted
website, resulting in the execution of arbitrary code in the context
of the current user.");
  #https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2015/ms15-124
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f205555e");
  #https://support.microsoft.com/en-us/help/3125869/ms15-124-vulnerability-in-internet-explorer-could-lead-to-aslr-bypass
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43c16242");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, RT, 2012, 8.1, RT 8.1, 2012 R2, and 10.

Refer to KB3125869 for additional information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-6083");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS15-124';
kbs = make_list('3104002', '3116869', '3116900', '3125869');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
os = get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);
os_build = get_kb_item("SMB/WindowsVersionBuild");

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if ("10" >< os && !("10240" == os_build || "10586" == os_build)) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# Assume applied until proven guilty
applied = TRUE;
if (
  # Windows 10
  hotfix_is_vulnerable(os:"10", sp:0, os_build:"10586", file:"mshtml.dll", version:"11.0.10586.20", min_version:"11.0.10586.0", dir:"\system32", bulletin:bulletin, kb:"3116900") ||
  hotfix_is_vulnerable(os:"10", sp:0, os_build:"10240", file:"mshtml.dll", version:"11.0.10240.16603", min_version:"11.0.10240.16000", dir:"\system32", bulletin:bulletin, kb:"3116869") ||

  # Windows 8.1 / Windows Server 2012 R2
  # Internet Explorer 11
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"mshtml.dll", version:"11.0.9600.18125", min_version:"11.0.9600.17000", dir:"\system32", bulletin:bulletin, kb:"3104002") ||

  # Windows 8 / Windows Server 2012
  # Internet Explorer 10
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"10.0.9200.21684", min_version:"10.0.9200.21000", dir:"\system32", bulletin:bulletin, kb:"3104002") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"10.0.9200.17568", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3104002") ||

  # Windows 7 / Server 2008 R2
  # Internet Explorer 10
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"10.0.9200.21684", min_version:"10.0.9200.21000", dir:"\system32", bulletin:bulletin, kb:"3104002") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"10.0.9200.17566", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3104002") ||
  # Internet Explorer 11
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"11.0.9600.18125", min_version:"11.0.9600.17000", dir:"\system32", bulletin:bulletin, kb:"3104002") ||
  # Internet Explorer 8
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"8.0.7601.23262", min_version:"8.0.7601.22000", dir:"\system32", bulletin:bulletin, kb:"3104002") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"8.0.7601.19058", min_version:"8.0.7601.17000", dir:"\system32", bulletin:bulletin, kb:"3104002") ||
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"9.0.8112.20838", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:"3104002") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"9.0.8112.16723", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"3104002") ||

  # Vista / Windows Server 2008
  # Internet Explorer 7
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"7.0.6002.23847", min_version:"7.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3104002") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"7.0.6002.19537", min_version:"7.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3104002") ||
  # Internet Explorer 8
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"8.0.6001.23765", min_version:"8.0.6001.23000", dir:"\system32", bulletin:bulletin, kb:"3104002") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"8.0.6001.19705", min_version:"8.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:"3104002") ||
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.20838", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:"3104002") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.16723", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"3104002")
) applied = FALSE;

######################################
# Report
######################################
if (!applied)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
