#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105081);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2017-3735",
    "CVE-2017-7154",
    "CVE-2017-7158",
    "CVE-2017-7159",
    "CVE-2017-7162",
    "CVE-2017-7172",
    "CVE-2017-7173",
    "CVE-2017-9798",
    "CVE-2017-12837",
    "CVE-2017-13847",
    "CVE-2017-13855",
    "CVE-2017-13862",
    "CVE-2017-13867",
    "CVE-2017-13868",
    "CVE-2017-13869",
    "CVE-2017-13872",
    "CVE-2017-13904",
    "CVE-2017-15422",
    "CVE-2017-1000254"
  );
  script_bugtraq_id(
    100515,
    100860,
    100872,
    101115,
    101981,
    102097,
    102098,
    102100,
    103134,
    103135
  );

  script_name(english:"macOS and Mac OS X Multiple Vulnerabilities (Security Update 2017-002 and 2017-005)");
  script_summary(english:"Checks for the presence of Security Update 2017-002 / 2017-005.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS or Mac OS X security update that
fixes multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Mac OS X 10.11.6 or Mac OS X 10.12.6 and is
missing a security update. It is therefore, affected by multiple
vulnerabilities affecting the following components :

  - apache
  - curl
  - IOAcceleratorFamily
  - IOKit
  - Kernel
  - OpenSSL
  - Screen Sharing Server");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT208331");
  script_set_attribute(attribute:"solution", value:
"Install Security Update 2017-005 or later for 10.11.x or
Security Update 2017-002 or later for 10.12.x.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7172");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mac OS X Root Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  patch = "2017-005";
else
  patch = "2017-002";

packages = get_kb_item_or_exit("Host/MacOSX/packages/boms", exit_code:1);
sec_boms_report = pgrep(
  pattern:"^com\.apple\.pkg\.update\.(security\.|os\.SecUpd).*bom$",
  string:packages
);
sec_boms = split(sec_boms_report, sep:'\n');

foreach package (sec_boms)
{
  # Grab patch year and number
  match = pregmatch(pattern:"[^0-9](20[0-9][0-9])[-.]([0-9]{3})[^0-9]", string:package);
  if (empty_or_null(match[1]) || empty_or_null(match[2]))
    continue;

  patch_found = check_patch(year:int(match[1]), number:int(match[2]));
  if (patch_found) exit(0, "The host has Security Update " + patch + " or later installed and is therefore not affected.");
}

report =  '\n  Missing security update : ' + patch;
report += '\n  Installed security BOMs : ';
if (sec_boms_report) report += str_replace(find:'\n', replace:'\n                            ', string:sec_boms_report);
else report += 'n/a';
report += '\n';

security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
