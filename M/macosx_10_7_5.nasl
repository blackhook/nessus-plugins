#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(62214);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2011-3026",
    "CVE-2011-3048",
    "CVE-2011-3368",
    "CVE-2011-3389",
    "CVE-2011-3607",
    "CVE-2011-4313",
    "CVE-2011-4317",
    "CVE-2011-4599",
    "CVE-2012-0021",
    "CVE-2012-0031",
    "CVE-2012-0053",
    "CVE-2012-0643",
    "CVE-2012-0652",
    "CVE-2012-0668",
    "CVE-2012-0670",
    "CVE-2012-0671",
    "CVE-2012-0831",
    "CVE-2012-1172",
    "CVE-2012-1173",
    "CVE-2012-1667",
    "CVE-2012-1823",
    "CVE-2012-2143",
    "CVE-2012-2311",
    "CVE-2012-2386",
    "CVE-2012-2688",
    "CVE-2012-3716",
    "CVE-2012-3719",
    "CVE-2012-3721",
    "CVE-2012-3722",
    "CVE-2012-3723"
  );
  script_bugtraq_id(
    47545,
    49778,
    49957,
    50494,
    50690,
    50802,
    51006,
    51407,
    51705,
    51706,
    51954,
    52049,
    52364,
    52830,
    52891,
    53388,
    53403,
    53445,
    53457,
    53579,
    53582,
    53584,
    53729,
    53772,
    54638,
    56241,
    56244,
    56246,
    56247
  );
  script_xref(name:"CERT", value:"864643");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");

  script_name(english:"Mac OS X 10.7.x < 10.7.5 Multiple Vulnerabilities (BEAST)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes multiple
security vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.7.x that is prior
to 10.7.5. The newer version contains multiple security-related fixes
for the following components :

  - Apache
  - BIND
  - CoreText
  - Data Security
  - ImageIO
  - Installer
  - International Components for Unicode
  - Kernel
  - Mail
  - PHP
  - Profile Manager
  - QuickLook
  - QuickTime
  - Ruby
  - USB");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Sep/94");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5501");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Sep/msg00004.html");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2011/09/23/chromeandbeast.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/tls-cbc.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X 10.7.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-2688");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP CGI Argument Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2022 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

os = get_kb_item("Host/MacOSX/Version");
if (!os)
{
  os = get_kb_item_or_exit("Host/OS");
  if ("Mac OS X" >!< os) audit(AUDIT_OS_NOT, "Mac OS X");

  c = get_kb_item("Host/OS/Confidence");
  if (c <= 70) exit(1, "Can't determine the host's OS with sufficient confidence.");
}
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

if (ereg(pattern:"Mac OS X 10\.7($|\.[0-4]([^0-9]|$))", string:os)) security_hole(0);
else exit(0, "The host is not affected as it is running "+os+".");
