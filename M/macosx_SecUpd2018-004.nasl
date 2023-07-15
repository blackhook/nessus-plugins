#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111136);
  script_version("1.8");
  script_cvs_date("Date: 2019/06/19 15:17:43");

  script_cve_id(
    "CVE-2017-0898",
    "CVE-2017-10784",
    "CVE-2017-14033",
    "CVE-2017-14064",
    "CVE-2017-17405",
    "CVE-2017-17742",
    "CVE-2018-3665",
    "CVE-2018-4178",
    "CVE-2018-4248",
    "CVE-2018-4259",
    "CVE-2018-4268",
    "CVE-2018-4269",
    "CVE-2018-4276",
    "CVE-2018-4277",
    "CVE-2018-4280",
    "CVE-2018-4283",
    "CVE-2018-4285",
    "CVE-2018-4286",
    "CVE-2018-4287",
    "CVE-2018-4288",
    "CVE-2018-4289",
    "CVE-2018-4291",
    "CVE-2018-4293",
    "CVE-2018-5383",
    "CVE-2018-6797",
    "CVE-2018-6913",
    "CVE-2018-6914",
    "CVE-2018-8777",
    "CVE-2018-8778",
    "CVE-2018-8779",
    "CVE-2018-8780"
  );
script_bugtraq_id(
    100853,
    100862,
    100868,
    100890,
    102204,
    103683,
    103684,
    103686,
    103693,
    103739,
    103767,
    103953,
    104460,
    104844,
    104879
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2018-7-9-4");

  script_name(english:"macOS and Mac OS X Multiple Vulnerabilities (Security Update 2018-004)");
  script_summary(english:"Checks for the presence of Security Update 2018-004.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS or Mac OS X security update that
fixes multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Mac OS X 10.11.6 or Mac OS X 10.12.6 and is
missing a security update. It is therefore, affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT208937");
  # https://lists.apple.com/archives/security-announce/2018/Jul/msg00005.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?981755ca");
  script_set_attribute(attribute:"solution", value:
"Install Security Update 2018-004 or later for 10.11.x or
Security Update 2018-004 or later for 10.12.x.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-4268");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/17");

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
include("lists.inc");

patch = "2018-004";
applicable_macos_versions = ['10.11.6', '10.12.6'];

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

matches = pregmatch(pattern:"Mac OS X ([0-9]+(\.[0-9]+)+)", string:os);
if (empty_or_null(matches)) exit(1, "Failed to parse the macOS / Mac OS X version ('" + os + "').");
version = matches[1];
if (!collib::contains(item:version, list:applicable_macos_versions)) audit(AUDIT_OS_SP_NOT_VULN);

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
