#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135901);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/12/06");

  script_cve_id("CVE-2020-0733");
  script_xref(name:"MSKB", value:"891716");

  script_name(english:"Windows Malicious Software Removal Tool Elevation of Privilege Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an antimalware application that is
affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"An elevation of privilege vulnerability exists when the Windows Malicious Software Removal Tool (MSRT) improperly handles junctions.
To exploit this vulnerability, an attacker would first have to gain execution on the victim system.
An attacker could then run a specially crafted application to elevate privileges'.");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0733
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e5172f5");
  # https://support.microsoft.com/en-us/help/890830/remove-specific-prevalent-malware-with-windows-malicious-software-remo
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0bcbff4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0733");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:malware_protection_engine");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_mrt_installed.nasl");
  script_require_keys("SMB/MRT/Version");
  script_require_ports(139, 445);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('smb_func.inc');

var version = get_kb_item_or_exit('SMB/MRT/Version');
var app = 'Microsoft Malicious Software Removal Tool';

var port, report;
if (ver_compare(ver:version, fix:'5.81.16832.1') == -1)
{
  port = get_kb_item('SMB/transport');
  if (isnull(port)) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Product           : Microsoft Malicious Software Removal Tool' +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.81.16832.1\n';
    security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
  }
  else security_report_v4(port:port, severity:SECURITY_WARNING);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, version);
