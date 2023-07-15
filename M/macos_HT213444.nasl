#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165106);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-32864",
    "CVE-2022-32883",
    "CVE-2022-32896",
    "CVE-2022-32900",
    "CVE-2022-32902",
    "CVE-2022-32908",
    "CVE-2022-32911",
    "CVE-2022-32917"
  );
  script_xref(name:"APPLE-SA", value:"HT213444");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/10/05");
  script_xref(name:"IAVA", value:"2022-A-0355-S");

  script_name(english:"macOS 12.x < 12.6 (HT213444)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS or Mac OS X security update or supplemental update that fixes multiple
vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 12.x prior to 12.6 Monterey. It is, therefore,
affected by multiple vulnerabilities :

  - Flaws with handling memory in the kernel. As a result, an app can be able to execute arbitrary code with
    kernel privileges or disclose kernel memory. (CVE-2022-32911, CVE-2022-32864)

  - Incorrect bounds checks in the kernel. As a result, an app can execute arbitrary code with kernel
    privileges. (CVE-2022-32917)

  - A logic issue in the Maps app. As a result an app can read sensitive location information.
    (CVE-2022-32883)

  - A flaw in the iMovie runtime. As a result a user can view sensitive information. (CVE-2022-32896)

  - A logic issue in the ATS component. As a result an app can bypass privacy preferences. (CVE-2022-32900)

  - A logic issue in PackageKit. As a result an app can gain elevated privileges. (CVE-2022-32900)

  - A memory corruption issue in the MediaLibrary component. As a result a user can elevate privileges.
    (CVE-2022-32908)

Note that Nessus has not tested for this issue but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-gb/HT213444");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 12.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32917");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();
var constraints = [
  {
    'min_version': '12.0',
    'fixed_version': '12.6',
    'fixed_display': 'macOS Monterey 12.6'
  }
];

vcf::apple::macos::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
