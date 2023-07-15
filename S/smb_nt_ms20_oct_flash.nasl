##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141493);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/22");

  script_cve_id("CVE-2020-9746");
  script_xref(name:"MSKB", value:"4580325");
  script_xref(name:"MSFT", value:"MS20-4580325");
  script_xref(name:"IAVA", value:"2020-A-0464");

  script_name(english:"KB4580325: Security update for Adobe Flash Player (October 2020)");
  script_summary(english:"Checks the version of the ActiveX control.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is affected by an arbitrary code
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update KB4580325. It is, therefore, affected by a NULL pointer dereference
flaw. An unauthenticated, remote attacker can exploit this, by inserting malicious strings in an HTTP response that is
by default delivered over TLS/SSL.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb20-58.html");
  # https://support.microsoft.com/en-us/help/4580325/security-update
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?31a777a0");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB4580325 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9746");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_activex_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS20-10';
kbs = make_list('4580325');
if (get_kb_item('Host/patch_management_checks')) 
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

productname = get_kb_item_or_exit('SMB/ProductName', exit_code:1);
if ('Windows 8' >< productname && 'Windows 8.1' >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

if (activex_init() != ACX_OK) audit(AUDIT_FN_FAIL, 'activex_init');

# Adobe Flash Player CLSID
clsid = '{D27CDB6E-AE6D-11cf-96B8-444553540000}';

file = activex_get_filename(clsid:clsid);
if (isnull(file))
{
  activex_end();
  audit(AUDIT_FN_FAIL, 'activex_get_filename', 'NULL');
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
iver = join(iver, sep:'.');

# all <= 32.0.0.433
fix = FALSE;
if(ver_compare(ver:iver, fix:'32.0.0.433', strict:FALSE) <= 0)
  fix = '32.0.0.445';

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
    replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
    security_report_v4(severity:SECURITY_HOLE, port:port, extra:hotfix_get_report() + report);
}
else audit(AUDIT_HOST_NOT, 'affected');
