#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130057);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2019-8701",
    "CVE-2019-8705",
    "CVE-2019-8717",
    "CVE-2019-8730",
    "CVE-2019-8745",
    "CVE-2019-8748",
    "CVE-2019-8755",
    "CVE-2019-8757",
    "CVE-2019-8758",
    "CVE-2019-8768",
    "CVE-2019-8769",
    "CVE-2019-8770",
    "CVE-2019-8772",
    "CVE-2019-8781",
    "CVE-2019-11041",
    "CVE-2019-11042"
  );
  script_xref(name:"APPLE-SA", value:"HT210634");

  script_name(english:"macOS < 10.15 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is prior
to 10.15. It is, therefore, affected by multiple vulnerabilities. 

  - An application may be able to execute arbitrary code with kernel privileges (CVE-2019-8748)

  - Multiple issues in PHP (CVE-2019-11041, CVE-2019-11042)

  - Processing a maliciously crafted movie may result in the disclosure of process memory (CVE-2019-8705)

  - The 'Share Mac Analytics' setting may not be disabled when a user deselects the switch to share analytics (CVE-2019-8757)

  - An application may be able to execute arbitrary code with system privileges (CVE-2019-8758)

  - A malicious application may be able to determine kernel memory layout (CVE-2019-8755)

  - An application may be able to execute arbitrary code with kernel privileges (CVE-2019-8717)

  - An application may be able to execute arbitrary code with kernel privileges (CVE-2019-8781)

  - A local user may be able to view a user's locked notes (CVE-2019-8730)

  - An attacker may be able to exfiltrate the contents of an encrypted PDF (CVE-2019-8772)

  - A malicious application may be able to access recent documents (CVE-2019-8770)

  - An application may be able to execute arbitrary code with system privileges (CVE-2019-8701)

  - Processing a maliciously crafted text file may lead to arbitrary code execution (CVE-2019-8745)

  - Visiting a maliciously crafted website may reveal browsing history (CVE-2019-8769)

  - A user may be unable to delete browsing history items (CVE-2019-8768)

Note that Nessus has not tested for this issue but has instead relied only on
the operating system's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT210634");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 10.15 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8781");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-8745");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Host/MacOSX/Version", "Host/OS");

  exit(0);
}

include('lists.inc');
include('vcf.inc');
include('vcf_extras_apple.inc');

app_info = vcf::apple::macos::get_app_info();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Build numbers from:
# https://en.wikipedia.org/wiki/MacOS#Release_history ->
#  https://en.wikipedia.org/wiki/MacOS_Sierra
#  https://en.wikipedia.org/wiki/MacOS_High_Sierra
#  https://en.wikipedia.org/wiki/MacOS_Mojave
#  https://en.wikipedia.org/wiki/MacOS_Catalina
constraints = [
  { 'min_version': '10.12', 'max_version': '10.15.0', 'fixed_build': '19A583', 'fixed_display': '10.15 Build 19A583' }
];

vcf::apple::macos::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

