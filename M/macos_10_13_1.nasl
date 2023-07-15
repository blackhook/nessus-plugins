#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104378);
  script_version("1.8");
  script_cvs_date("Date: 2019/06/19 15:17:43");

  script_cve_id(
    "CVE-2017-1000100",
    "CVE-2017-1000101",
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
    "CVE-2017-13786",
    "CVE-2017-13799",
    "CVE-2017-13800",
    "CVE-2017-13801",
    "CVE-2017-13804",
    "CVE-2017-13808",
    "CVE-2017-13811",
    "CVE-2017-13852",
    "CVE-2017-13907",
    "CVE-2017-7170",
    "CVE-2018-4390",
    "CVE-2018-4391"
  );
  script_bugtraq_id(
    100249,
    100286,
    100913,
    100914,
    101274,
    99938,
    99939,
    99940,
    99941
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2017-10-31-2");
  script_xref(name:"IAVA", value:"2017-A-0310");

  script_name(english:"macOS 10.13.x < 10.13.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Mac OS X / macOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple security
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X that is 10.13.x
prior to 10.13.1. It is, therefore, affected by multiple
vulnerabilities in the following components :

  - APFS
  - curl
  - Dictionary Widget
  - Kernel
  - StreamingZip
  - tcpdump
  - Wi-Fi

Note that successful exploitation of the most serious issues can
result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT208221");
  # https://lists.apple.com/archives/security-announce/2017/Oct/msg00001.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3881783e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS version 10.13.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7170");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/OS");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

os = get_kb_item("Host/MacOSX/Version");
if (!os)
{
  os = get_kb_item_or_exit("Host/OS");
  if ("Mac OS X" >!< os) audit(AUDIT_OS_NOT, "macOS / Mac OS X");

  c = get_kb_item("Host/OS/Confidence");
  if (c <= 70) exit(1, "Can't determine the host's OS with sufficient confidence.");
}
if (!os) audit(AUDIT_OS_NOT, "macOS / Mac OS X");

matches = pregmatch(pattern:"Mac OS X ([0-9]+(\.[0-9]+)+)", string:os);
if (empty_or_null(matches)) exit(1, "Failed to parse the macOS / Mac OS X version ('" + os + "').");

version = matches[1];
fixed_version = "10.13.1";

if (version !~"^10\.13($|[^0-9])")
  audit(AUDIT_OS_NOT, "macOS 10.13.x");

if (ver_compare(ver:version, fix:'10.13.1', strict:FALSE) == -1)
{
  security_report_v4(
    port:0,
    severity:SECURITY_HOLE,
    extra:
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version +
      '\n'
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "macOS / Mac OS X", version);
