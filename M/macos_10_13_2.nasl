#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105080);
  script_version("1.12");
  script_cvs_date("Date: 2019/06/19 15:17:43");

  script_cve_id(
    "CVE-2017-1000254",
    "CVE-2017-13847",
    "CVE-2017-13848",
    "CVE-2017-13855",
    "CVE-2017-13858",
    "CVE-2017-13860",
    "CVE-2017-13862",
    "CVE-2017-13865",
    "CVE-2017-13867",
    "CVE-2017-13868",
    "CVE-2017-13869",
    "CVE-2017-13871",
    "CVE-2017-13872",
    "CVE-2017-13875",
    "CVE-2017-13876",
    "CVE-2017-13878",
    "CVE-2017-13883",
    "CVE-2017-13886",
    "CVE-2017-13887",
    "CVE-2017-13892",
    "CVE-2017-13904",
    "CVE-2017-13905",
    "CVE-2017-13911",
    "CVE-2017-15422",
    "CVE-2017-3735",
    "CVE-2017-5754",
    "CVE-2017-7151",
    "CVE-2017-7154",
    "CVE-2017-7155",
    "CVE-2017-7158",
    "CVE-2017-7159",
    "CVE-2017-7162",
    "CVE-2017-7163",
    "CVE-2017-7171",
    "CVE-2017-7172",
    "CVE-2017-7173",
    "CVE-2017-9798"
  );
  script_bugtraq_id(
    100515,
    100872,
    101115,
    101981,
    102097,
    102098,
    102099,
    102100,
    102378,
    103134,
    103135
  );
  script_xref(name:"IAVA", value:"2018-A-0019");

  script_name(english:"macOS 10.13.x < 10.13.2 Multiple Vulnerabilities (Meltdown)");
  script_summary(english:"Checks the version of Mac OS X / macOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple security
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X that is 10.13.x
prior to 10.13.2. It is, therefore, affected by multiple
vulnerabilities in the following components :

  - apache
  - curl
  - Directory Utility
  - IOAcceleratorFamily
  - IOKit
  - Intel Graphics Driver
  - Kernel
  - Mail
  - Mail Drafts
  - OpenSSL
  - Screen Sharing Server

Note that successful exploitation of the most serious issues can
result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT208331");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT208394");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS version 10.13.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7172");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mac OS X Root Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
fixed_version = "10.13.2";

if (version !~"^10\.13($|[^0-9])")
  audit(AUDIT_OS_NOT, "macOS 10.13.x");

if (ver_compare(ver:version, fix:'10.13.2', strict:FALSE) == -1)
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
