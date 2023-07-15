#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129467);
  script_version("1.4");
  script_cvs_date("Date: 2020/01/07");

  script_cve_id("CVE-2019-8641");
  script_bugtraq_id(109332);
  script_xref(name:"APPLE-SA", value:"HT210589");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2019-9-26-2");

  script_name(english:"macOS 10.14.x < 10.14.6 SU2 / 10.13.x < 10.13.6 Update 2019-005 / 10.12.x < 10.12.6 Update 2019-005 Out-of-Bounds Read Vulnerability");
  script_summary(english:"Checks the version of Mac OS X / macOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes an out-of-bounds read vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 10.14.x prior
to 10.14.6 Supplemental Update 2, 10.13.x prior to 10.13.6 Security Update
2019-005, or 10.12.x prior to 10.12.6 Security Update 2019-005. It is,
therefore, affected by an out-of-bounds read vulnerability. An attacker could
exploit this vulnerability to cause an application crash, or potentially
achieve arbitrary code execution.

Note that Nessus has not tested for this issue but has instead relied only on
the operating system's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT210589");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 10.14.x < 10.14.6 SU2 / 10.13.x < 10.13.6 Update 2019-005 /
10.12.x < 10.12.6 Update 2019-005 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8641");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/OS");

  exit(0);
}

include('lists.inc');
include('vcf.inc');
include('vcf_extras_apple.inc');

app_info = vcf::apple::macos::get_app_info();

# Build numbers from:
# https://en.wikipedia.org/wiki/MacOS#Release_history ->
#  https://en.wikipedia.org/wiki/MacOS_Sierra
#  https://en.wikipedia.org/wiki/MacOS_High_Sierra
#  https://en.wikipedia.org/wiki/MacOS_Mojave
#  ...
constraints = [
  { 'min_version': '10.12', 'max_version': '10.12.6', 'fixed_build': '16G2136', 'fixed_display': '10.12.6 Security Update 2019-005' },
  { 'min_version': '10.13', 'max_version': '10.13.6', 'fixed_build': '17G8037', 'fixed_display': '10.13.6 Security Update 2019-005' },
  { 'min_version': '10.14', 'max_version': '10.14.6', 'fixed_build': '18G103', 'fixed_display': '10.14.6 Supplemental Update 2' }
];

vcf::apple::macos::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

