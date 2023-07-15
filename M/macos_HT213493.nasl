#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166457);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/15");

  script_cve_id(
    "CVE-2022-28739",
    "CVE-2022-32862",
    "CVE-2022-32941",
    "CVE-2022-32944",
    "CVE-2022-37434",
    "CVE-2022-42798",
    "CVE-2022-42800",
    "CVE-2022-42825"
  );
  script_xref(name:"APPLE-SA", value:"HT213493");
  script_xref(name:"IAVA", value:"2022-A-0442-S");

  script_name(english:"macOS 11.x < 11.7.1 Multiple Vulnerabilities (HT213493)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 11.x prior to 11.7.1. It is, therefore, affected by
multiple vulnerabilities :

  - A remote user may be able to cause unexpected app termination or arbitrary code execution (CVE-2022-28739)

  - An app with root privileges may be able to access private information. (CVE-2022-32862)

  - An app may be able to modify protected parts of the file system (CVE-2022-42825)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213493");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 11.7.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28739");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-37434");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();

var constraints = [
  { 'min_version' : '11.0', 'fixed_version' : '11.7.1', 'fixed_display' : 'macOS Big Sur 11.7.1' }
];

vcf::apple::macos::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
