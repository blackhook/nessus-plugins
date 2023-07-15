#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111137);
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
    "CVE-2018-4456",
    "CVE-2018-4470",
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
    106779
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2018-7-9-4");

  script_name(english:"macOS 10.13.x < 10.13.6 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Mac OS X / macOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple security
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is
10.13.x prior to 10.13.6. It is, therefore, affected by multiple
vulnerabilities.

Note that successful exploitation of the most serious issues can
result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT208937");
  # https://lists.apple.com/archives/security-announce/2018/Jul/msg00005.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?981755ca");
  # https://lists.apple.com/archives/security-announce/2018/Jul/msg00008.html 
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f04312a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS version 10.13.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-4259");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
fix = "10.13.6";

if (version !~"^10\.13($|[^0-9])")
  audit(AUDIT_OS_NOT, "macOS 10.13.x");

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  security_report_v4(
    port:0,
    severity:SECURITY_HOLE,
    extra:
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n'
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "macOS / Mac OS X", version);
