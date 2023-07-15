#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87893);
  script_version("1.9");
  script_cvs_date("Date: 2018/11/15 20:50:28");

  script_xref(name:"MSKB", value:"3118753");

  script_name(english:"MS KB3118753: Update for ActiveX Kill Bits");
  script_summary(english:"Checks if kill bits have been set.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is missing an update that disables selected
ActiveX controls.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing one or more kill bits for ActiveX
controls that are known to contain vulnerabilities.

If any of these ActiveX controls are ever installed on the remote
host, either now or in the future, they would expose the host to
various security issues.

Note that the affected controls are from third-party vendors that have
asked Microsoft to prevent their controls from being run in Internet
Explorer.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2016/3118753");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, RT, 2012, 8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Listed as critical by vendor.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible", "SMB/IE/Version");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_activex_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/IE/Version");
get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);
if ("Windows Embedded" >< productname) exit(0, "The host is running "+productname+" and hence is not affected.");
if (activex_init() != ACX_OK) exit(1, "Unable to initialize the ActiveX API.");

# Test each control.
info = "";
clsid = '{D4C0DB38-B682-42A8-AF62-DB9247543354}';

if (activex_get_killbit(clsid:clsid) == 0)
{
  info += '  ' + clsid + '\n';
}

activex_end();

if (!empty_or_null(info))
{
  if (report_verbosity > 0)
  {
    report =
      '\nThe kill bit has not been set for the following control :\n\n'+
      info;

    hotfix_add_report(report);
  }
  else hotfix_add_report();

  hotfix_security_hole();
}
else audit(AUDIT_HOST_NOT, 'affected');
