#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(39783);
  script_version("1.31");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/05");

  script_cve_id("CVE-2009-1136");
  script_bugtraq_id(35642);
  script_xref(name:"IAVA", value:"2009-A-0069-S");
  script_xref(name:"MSFT", value:"MS09-043");
  script_xref(name:"MSKB", value:"973472");
  script_xref(name:"Secunia", value:"35800");

  script_name(english:"MS09-043: Vulnerabilities in Microsoft Office Web Components Control Could Allow Remote Code Execution (973472)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an ActiveX control that could allow
remote code execution.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host includes Microsoft Office Web Components, a
collection of Component Object Model (COM) controls for publishing and
viewing spreadsheets, charts, and databases on the web. 

A privately reported vulnerability in Microsoft Office Web Components
reportedly can be abused to corrupt the system state and allow execution
of arbitrary code.");
  # https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2009/973472
  script_set_attribute(attribute:"see_also", value:"https://www.nessus.org/u?510786ed");
  # https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2009/ms09-043
  script_set_attribute(attribute:"see_also", value:"https://www.nessus.org/u?682ca4b4");
  script_set_attribute(attribute:"solution", value:
  "Microsoft has released a set of patches for Office XP and 2003, as well
  as for Microsoft ISA server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-1136");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft OWC Spreadsheet msDataSourceObject Memory Corruption');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"D2ExploitPack");
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "smb_nt_ms09-043.nasl");
  script_require_keys("SMB/WindowsVersion", "SMB/Missing/MS09-043");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_activex_func.inc");


if (!get_kb_item("SMB/Missing/MS09-043")) exit(0);
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


if (activex_init() != ACX_OK) exit(0);


# Test each control.
info = '';
clsids = make_list(
  "{0002E541-0000-0000-C000-000000000046}",
  "{0002E559-0000-0000-C000-000000000046}"
);

var clsid;
foreach clsid (clsids)
{
  file = activex_get_filename(clsid:clsid);
  if (file)
  {
    if (activex_get_killbit(clsid:clsid) == 0)
    {
      version = activex_get_fileversion(clsid:clsid);
      if (!version) version = "Unknown";

      info += 
        '\n' +
        '  Class Identifier : ' + clsid + '\n' +
        '  Filename         : ' + file + '\n' +
        '  Version          : ' + version + '\n' 
      ;
      if (!thorough_tests) break;
    }
  }
}
activex_end();


if (info)
{
  if (max_index(split(info)) > 4) s = "s";
  else s = "";

  report =
    '\n' +
    'The kill bit has not been set for the following control' + s + ' :\n' +
    '\n' +
    info
  ;

  if (!thorough_tests)
  {
    report += '\n' + 
      'Note that Nessus did not check whether there were other kill bits\n' + 
      'that have not been set because the \'Perform thorough tests\' setting\n' + 
      'was not enabled when this scan was run.\n' ;
  }
  security_report_v4(port:kb_smb_transport(), extra:report, severity:SECURITY_HOLE);
}