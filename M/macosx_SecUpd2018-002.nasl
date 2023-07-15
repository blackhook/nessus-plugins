#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108787);
  script_version("1.6");
  script_cvs_date("Date: 2019/06/19 15:17:43");

  script_cve_id(
    "CVE-2017-13890",
    "CVE-2017-13911",
    "CVE-2017-15412",
    "CVE-2017-7151",
    "CVE-2017-8816",
    "CVE-2018-4104",
    "CVE-2018-4106",
    "CVE-2018-4108",
    "CVE-2018-4112",
    "CVE-2018-4131",
    "CVE-2018-4136",
    "CVE-2018-4139",
    "CVE-2018-4144",
    "CVE-2018-4150",
    "CVE-2018-4151",
    "CVE-2018-4154",
    "CVE-2018-4155",
    "CVE-2018-4156",
    "CVE-2018-4158",
    "CVE-2018-4175",
    "CVE-2018-4176"
  );
  script_bugtraq_id(
    101998,
    102098,
    103579,
    103581,
    103582
  );
  script_name(english:"macOS and Mac OS X Multiple Vulnerabilities (Security Update 2018-002)");
  script_summary(english:"Checks for the presence of Security Update 2018-002.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS or Mac OS X security update that
fixes multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Mac OS X 10.11.6 or Mac OS X 10.12.6 and is
missing a security update. It is therefore, affected by multiple
vulnerabilities affecting the following components :

  - ATS
  - CFNetwork Session
  - CoreFoundation
  - CoreTypes
  - curl
  - Disk Images
  - iCloud Drive
  - Kernel
  - kext tools
  - LaunchServices
  - PluginKit
  - Security
  - Storage
  - Terminal");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT208692");
  # https://lists.apple.com/archives/security-announce/2018/Mar/msg00004.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0e00f71");
  script_set_attribute(attribute:"solution", value:
"Install Security Update 2018-002 or later for 10.11.x or
Security Update 2018-002 or later for 10.12.x.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-13911");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
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
  patch = "2018-002";
else
  patch = "2018-002";

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
