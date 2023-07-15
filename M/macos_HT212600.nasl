#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152036);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/05");

  script_cve_id(
    "CVE-2021-30672",
    "CVE-2021-30677",
    "CVE-2021-30703",
    "CVE-2021-30731",
    "CVE-2021-30733",
    "CVE-2021-30759",
    "CVE-2021-30760",
    "CVE-2021-30765",
    "CVE-2021-30766",
    "CVE-2021-30768",
    "CVE-2021-30775",
    "CVE-2021-30776",
    "CVE-2021-30777",
    "CVE-2021-30780",
    "CVE-2021-30781",
    "CVE-2021-30782",
    "CVE-2021-30783",
    "CVE-2021-30785",
    "CVE-2021-30787",
    "CVE-2021-30788",
    "CVE-2021-30789",
    "CVE-2021-30790",
    "CVE-2021-30793",
    "CVE-2021-30796",
    "CVE-2021-30799",
    "CVE-2021-30805"
  );
  script_xref(name:"APPLE-SA", value:"HT212600");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2021-07-21");
  script_xref(name:"IAVA", value:"2021-A-0349-S");

  script_name(english:"macOS 10.15.x < Catalina Security Update 2021-004 Catalina (HT212600)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a version of macOS / Mac OS X that is 10.15.x prior to 10.15.7 Security Update 2021-004
Catalina. It is, therefore, affected by multiple vulnerabilities, including the following:

  - An application may be able to execute arbitrary code with kernel privileges
    (CVE-2021-30805)

  - Opening a maliciously crafted file may lead to unexpected application termination or arbitrary code execution
    (CVE-2021-30790)

  - A malicious application may be able to gain root privileges (CVE-2021-30672)

Note that Nessus has not tested for this issue but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 0.0.x prior to Catalina Security Update 2021-004
Catalina. It is, therefore, affected by multiple vulnerabilities : Note that Nessus has not tested for this issue but
has instead relied only on the operating system's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT212600");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 10.15.x < Catalina Security Update 2021-004 Catalina or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30805");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();

var constraints = [
  {
    'max_version' : '10.15.7',
    'min_version' : '10.15',
    'fixed_build': '19H1323',
    'fixed_display' : '10.15.7 Security Update 2021-004 Catalina'
  }
];

vcf::apple::macos::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);