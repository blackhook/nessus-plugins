#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100767);
  script_version("1.10");
  script_cvs_date("Date: 2018/08/03 11:35:09");

  script_cve_id("CVE-2017-0283", "CVE-2017-8527");
  script_bugtraq_id(98920, 98933);
  script_xref(name:"MSKB", value:"4023307");
  script_xref(name:"MSFT", value:"MS17-4023307");
  script_xref(name:"IAVA", value:"2017-A-0180");

  script_name(english:"KB4023307: Security Update for the Windows Uniscribe Remote Code Execution Vulnerability for Microsoft Silverlight 5 (June 2017)");
  script_summary(english:"Checks the version of npctrl.dll.");

  script_set_attribute(attribute:"synopsis", value:
"A web application framework running on the remote host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Silverlight 5 installed on the remote Windows host is
missing security update KB4023307. It is, therefore, affected by
multiple vulnerabilities :

  - A remote code execution vulnerability exists in
    Windows Uniscribe software due to improper handling of
    objects in memory. An unauthenticated, remote attacker
    can exploit this, by convincing a user to visit a
    specially crafted website or to open a specially crafted
    document file, to execute arbitrary code in the context
    of the current user. (CVE-2017-0283)

  - A remote code execution vulnerability exists in the
    Windows font library due to improper handling of
    embedded fonts. An unauthenticated, remote attacker can
    exploit this, by convincing a user to visit a specially
    crafted website or open a specially crafted Microsoft
    document, to execute arbitrary code in the context of
    the current user. (CVE-2017-8527)");
  # https://support.microsoft.com/en-us/help/4023307/windows-uniscribe-remote-code-execution-vulnerability-june-13-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?73572b10");
  # https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-0283
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?36ab262f");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-8527
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c2ca141");
  script_set_attribute(attribute:"solution", value:
"Apply security update KB4023307.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("silverlight_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/Silverlight/Version");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_fixes_summary.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

version = get_kb_item_or_exit("SMB/Silverlight/Version");
bulletin = "MS17-06";

if (!isnull(version) && version =~ "^5\.")
{
  fix = "5.1.50907.0";
}
else audit(AUDIT_HOST_NOT, 'affected');

if (ver_compare(ver:version, fix:fix) == -1)
{
  path = get_kb_item("SMB/Silverlight/Path");
  if (isnull(path)) path = 'n/a';

  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';


  smb_hf_add(bulletin:bulletin, kb:"4023307");
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  security_report_v4(port:get_kb_item("SMB/transport"), severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_HOST_NOT, 'affected');
