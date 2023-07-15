#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(118573);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/16");

  script_cve_id(
    "CVE-2017-0898",
    "CVE-2017-10784",
    "CVE-2017-12613",
    "CVE-2017-12618",
    "CVE-2017-14033",
    "CVE-2017-14064",
    "CVE-2017-17405",
    "CVE-2017-17742",
    "CVE-2018-3640",
    "CVE-2018-3646",
    "CVE-2018-4126",
    "CVE-2018-4153",
    "CVE-2018-4203",
    "CVE-2018-4242",
    "CVE-2018-4259",
    "CVE-2018-4286",
    "CVE-2018-4287",
    "CVE-2018-4288",
    "CVE-2018-4291",
    "CVE-2018-4295",
    "CVE-2018-4304",
    "CVE-2018-4308",
    "CVE-2018-4310",
    "CVE-2018-4326",
    "CVE-2018-4331",
    "CVE-2018-4334",
    "CVE-2018-4340",
    "CVE-2018-4341",
    "CVE-2018-4346",
    "CVE-2018-4348",
    "CVE-2018-4368",
    "CVE-2018-4371",
    "CVE-2018-4393",
    "CVE-2018-4394",
    "CVE-2018-4395",
    "CVE-2018-4398",
    "CVE-2018-4400",
    "CVE-2018-4401",
    "CVE-2018-4402",
    "CVE-2018-4406",
    "CVE-2018-4407",
    "CVE-2018-4408",
    "CVE-2018-4410",
    "CVE-2018-4411",
    "CVE-2018-4412",
    "CVE-2018-4413",
    "CVE-2018-4415",
    "CVE-2018-4417",
    "CVE-2018-4419",
    "CVE-2018-4420",
    "CVE-2018-4422",
    "CVE-2018-4423",
    "CVE-2018-4425",
    "CVE-2018-6797",
    "CVE-2018-6914",
    "CVE-2018-8777",
    "CVE-2018-8778",
    "CVE-2018-8779",
    "CVE-2018-8780"
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2018-10-30-2");
  script_xref(name:"IAVA", value:"2021-A-0356-S");

  script_name(english:"macOS and Mac OS X Multiple Vulnerabilities (Security Update 2018-005)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS or Mac OS X security update that
fixes multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Mac OS X 10.12.6 and is missing a security
update. It is therefore, affected by multiple vulnerabilities
affecting the following components :

  - afpserver
  - AppleGraphicsControl
  - APR
  - ATS
  - CFNetwork
  - CoreAnimation
  - CoreCrypto
  - CoreFoundation
  - CUPS
  - Dictionary
  - dyld
  - Foundation
  - Heimdal
  - Hypervisor
  - ICU
  - Intel Graphics Driver
  - IOGraphics
  - IOHIDFamily
  - IOKit
  - IOUserEthernet
  - IPSec
  - Kernel
  - Login Window
  - mDNSOffloadUserClient
  - MediaRemote
  - Microcode
  - Perl
  - Ruby
  - Security
  - Spotlight
  - Symptom Framework
  - WiFi");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT209193");
  # https://lists.apple.com/archives/security-announce/2018/Oct/msg00003.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f0681c90");
  script_set_attribute(attribute:"solution", value:
"Install Security Update 2018-005 or later for 10.12.x.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-4331");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-4310");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (!preg(pattern:"Mac OS X 10\.12\.6([^0-9]|$)", string:os))
  audit(AUDIT_OS_NOT, "Mac OS X 10.12.6");

patch = "2018-005";

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
