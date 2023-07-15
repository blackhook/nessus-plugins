#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104379);
  script_version("1.10");
  script_cvs_date("Date: 2019/06/19 15:17:43");

  script_cve_id(
    "CVE-2016-0736",
    "CVE-2016-2161",
    "CVE-2016-4736",
    "CVE-2016-5387",
    "CVE-2016-8740",
    "CVE-2016-8743",
    "CVE-2017-1000100",
    "CVE-2017-1000101",
    "CVE-2017-10140",
    "CVE-2017-11103",
    "CVE-2017-11108",
    "CVE-2017-11541",
    "CVE-2017-11542",
    "CVE-2017-11543",
    "CVE-2017-12893",
    "CVE-2017-12894",
    "CVE-2017-12895",
    "CVE-2017-12896",
    "CVE-2017-12897",
    "CVE-2017-12898",
    "CVE-2017-12899",
    "CVE-2017-12900",
    "CVE-2017-12901",
    "CVE-2017-12902",
    "CVE-2017-12985",
    "CVE-2017-12986",
    "CVE-2017-12987",
    "CVE-2017-12988",
    "CVE-2017-12989",
    "CVE-2017-12990",
    "CVE-2017-12991",
    "CVE-2017-12992",
    "CVE-2017-12993",
    "CVE-2017-12994",
    "CVE-2017-12995",
    "CVE-2017-12996",
    "CVE-2017-12997",
    "CVE-2017-12998",
    "CVE-2017-12999",
    "CVE-2017-13000",
    "CVE-2017-13001",
    "CVE-2017-13002",
    "CVE-2017-13003",
    "CVE-2017-13004",
    "CVE-2017-13005",
    "CVE-2017-13006",
    "CVE-2017-13007",
    "CVE-2017-13008",
    "CVE-2017-13009",
    "CVE-2017-13010",
    "CVE-2017-13011",
    "CVE-2017-13012",
    "CVE-2017-13013",
    "CVE-2017-13014",
    "CVE-2017-13015",
    "CVE-2017-13016",
    "CVE-2017-13017",
    "CVE-2017-13018",
    "CVE-2017-13019",
    "CVE-2017-13020",
    "CVE-2017-13021",
    "CVE-2017-13022",
    "CVE-2017-13023",
    "CVE-2017-13024",
    "CVE-2017-13025",
    "CVE-2017-13026",
    "CVE-2017-13027",
    "CVE-2017-13028",
    "CVE-2017-13029",
    "CVE-2017-13030",
    "CVE-2017-13031",
    "CVE-2017-13032",
    "CVE-2017-13033",
    "CVE-2017-13034",
    "CVE-2017-13035",
    "CVE-2017-13036",
    "CVE-2017-13037",
    "CVE-2017-13038",
    "CVE-2017-13039",
    "CVE-2017-13040",
    "CVE-2017-13041",
    "CVE-2017-13042",
    "CVE-2017-13043",
    "CVE-2017-13044",
    "CVE-2017-13045",
    "CVE-2017-13046",
    "CVE-2017-13047",
    "CVE-2017-13048",
    "CVE-2017-13049",
    "CVE-2017-13050",
    "CVE-2017-13051",
    "CVE-2017-13052",
    "CVE-2017-13053",
    "CVE-2017-13054",
    "CVE-2017-13055",
    "CVE-2017-13077",
    "CVE-2017-13078",
    "CVE-2017-13080",
    "CVE-2017-13687",
    "CVE-2017-13688",
    "CVE-2017-13689",
    "CVE-2017-13690",
    "CVE-2017-13725",
    "CVE-2017-13782",
    "CVE-2017-13799",
    "CVE-2017-13801",
    "CVE-2017-13804",
    "CVE-2017-13807",
    "CVE-2017-13808",
    "CVE-2017-13809",
    "CVE-2017-13810",
    "CVE-2017-13811",
    "CVE-2017-13812",
    "CVE-2017-13813",
    "CVE-2017-13814",
    "CVE-2017-13815",
    "CVE-2017-13817",
    "CVE-2017-13818",
    "CVE-2017-13819",
    "CVE-2017-13820",
    "CVE-2017-13821",
    "CVE-2017-13822",
    "CVE-2017-13823",
    "CVE-2017-13824",
    "CVE-2017-13825",
    "CVE-2017-13828",
    "CVE-2017-13829",
    "CVE-2017-13830",
    "CVE-2017-13831",
    "CVE-2017-13833",
    "CVE-2017-13834",
    "CVE-2017-13836",
    "CVE-2017-13838",
    "CVE-2017-13840",
    "CVE-2017-13841",
    "CVE-2017-13842",
    "CVE-2017-13843",
    "CVE-2017-13846",
    "CVE-2017-13906",
    "CVE-2017-13908",
    "CVE-2017-3167",
    "CVE-2017-3169",
    "CVE-2017-5130",
    "CVE-2017-5969",
    "CVE-2017-7132",
    "CVE-2017-7150",
    "CVE-2017-7170",
    "CVE-2017-7376",
    "CVE-2017-7659",
    "CVE-2017-7668",
    "CVE-2017-7679",
    "CVE-2017-9049",
    "CVE-2017-9050",
    "CVE-2017-9788",
    "CVE-2017-9789"
  );
  script_bugtraq_id(
    100249,
    100286,
    100913,
    100914,
    101177,
    101274,
    101482,
    102100,
    91816,
    93055,
    94650,
    95076,
    95077,
    95078,
    96188,
    98568,
    98601,
    98877,
    99132,
    99134,
    99135,
    99137,
    99170,
    99551,
    99568,
    99569,
    99938,
    99939,
    99940,
    99941
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2017-10-31-2");
  script_xref(name:"IAVA", value:"2017-A-0310");

  script_name(english:"macOS and Mac OS X Multiple Vulnerabilities (Security Update 2017-001 and 2017-004)");
  script_summary(english:"Checks for the presence of Security Update 2017-004.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS or Mac OS X security update that
fixes multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Mac OS X 10.11.6 or Mac OS X 10.12.6 and is
missing a security update. It is therefore, affected by multiple
vulnerabilities affecting the following components :

  - 802.1X
  - apache
  - AppleScript
  - ATS
  - Audio
  - CFString
  - CoreText
  - curl
  - Dictionary Widget
  - file
  - Fonts
  - fsck_msdos
  - HFS
  - Heimdal
  - HelpViewer
  - ImageIO
  - Kernel
  - libarchive
  - Open Scripting Architecture
  - PCRE
  - Postfix
  - Quick Look
  - QuickTime
  - Remote Management
  - Sandbox
  - StreamingZip
  - tcpdump
  - Wi-Fi");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT208221");
  # https://lists.apple.com/archives/security-announce/2017/Oct/msg00001.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3881783e");
  script_set_attribute(attribute:"solution", value:
"Install Security Update 2017-004 or later for 10.11.x or
Security Update 2017-001 or later for 10.12.x.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7376");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
  patch = "2017-004";
else
  patch = "2017-001";

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

security_report_v4(port:0, severity:SECURITY_HOLE, extra:report, xss:TRUE);
