#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106297);
  script_version("1.10");
  script_cvs_date("Date: 2019/06/19 15:17:43");

  script_cve_id(
    "CVE-2017-5705",
    "CVE-2017-5708",
    "CVE-2017-5754",
    "CVE-2018-4083",
    "CVE-2018-4084",
    "CVE-2018-4085",
    "CVE-2018-4086",
    "CVE-2018-4094",
    "CVE-2018-4097",
    "CVE-2018-4098",
    "CVE-2018-4100",
    "CVE-2018-4189",
    "CVE-2018-4298"
  );
  script_bugtraq_id(
    101917,
    101921,
    102378,
    102772,
    102782,
    102785,
    103330
  );
  script_xref(name:"IAVA", value:"2018-A-0019");

  script_name(english:"macOS and Mac OS X Multiple Vulnerabilities (Security Update 2018-001) (Meltdown)");
  script_summary(english:"Checks for the presence of Security Update 2017-002 / 2017-005.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS or Mac OS X security update that
fixes multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Mac OS X 10.11.6 or Mac OS X 10.12.6 and is
missing a security update. It is therefore, affected by multiple
vulnerabilities affecting the following components :

  - Audio
  - curl
  - IOHIDFamily
  - Kernel
  - LinkPresentation
  - QuartzCore
  - Sandbox
  - Security
  - WebKit
  - Wi-Fi");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT208465");
  # https://lists.apple.com/archives/security-announce/2018/Jan/msg00001.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?19644313");
  script_set_attribute(attribute:"solution", value:
"Install Security Update 2018-001 or later for 10.11.x or
Security Update 2018-001 or later for 10.12.x.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-4189");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/MacOSX/packages/boms");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Compare 2 patch numbers to determine if patch requirements are satisfied.
# Return true if this patch or a later patch is applied
# Return false otherwise
function check_patch(year, number)
{
  local_var p_split = split(patch, sep:"-");
  local_var p_year  = int( p_split[0]);
  local_var p_num   = int( p_split[1]);

  if (year >  p_year) return TRUE;
  else if (year <  p_year) return FALSE;
  else if (number >=  p_num) return TRUE;
  else return FALSE;
}

get_kb_item_or_exit("Host/local_checks_enabled");
os = get_kb_item_or_exit("Host/MacOSX/Version");

if (!preg(pattern:"Mac OS X 10\.(11\.6|12\.6)([^0-9]|$)", string:os))
  audit(AUDIT_OS_NOT, "Mac OS X 10.11.6 or Mac OS X 10.12.6");

if ("10.11.6" >< os)
  patch = "2018-001";
else
  patch = "2018-001";

packages = get_kb_item_or_exit("Host/MacOSX/packages/boms", exit_code:1);
sec_boms_report = pgrep(
  pattern:"^com\.apple\.pkg\.update\.(security\.|os\.SecUpd).*bom$",
  string:packages
);
sec_boms = split(sec_boms_report, sep:'\n');

foreach package (sec_boms)
{
  # Grab patch year and number
  matches = pregmatch(pattern:"[^0-9](20[0-9][0-9])[-.]([0-9]{3})[^0-9]", string:package);
  if (empty_or_null(matches)) continue;
  if (empty_or_null(matches[1]) || empty_or_null(matches[2]))
    continue;

  patch_found = check_patch(year:int(matches[1]), number:int(matches[2]));
  if (patch_found) exit(0, "The host has Security Update " + patch + " or later installed and is therefore not affected.");
}

report =  '\n  Missing security update : ' + patch;
report += '\n  Installed security BOMs : ';
if (sec_boms_report) report += str_replace(find:'\n', replace:'\n                            ', string:sec_boms_report);
else report += 'n/a';
report += '\n';

security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
