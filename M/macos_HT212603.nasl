#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152039);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/20");

  script_cve_id(
    "CVE-2021-30672",
    "CVE-2021-30677",
    "CVE-2021-30703",
    "CVE-2021-30733",
    "CVE-2021-30759",
    "CVE-2021-30760",
    "CVE-2021-30765",
    "CVE-2021-30766",
    "CVE-2021-30777",
    "CVE-2021-30780",
    "CVE-2021-30781",
    "CVE-2021-30782",
    "CVE-2021-30783",
    "CVE-2021-30787",
    "CVE-2021-30788",
    "CVE-2021-30790",
    "CVE-2021-30793",
    "CVE-2021-30796",
    "CVE-2021-30799",
    "CVE-2021-30805"
  );
  script_xref(name:"APPLE-SA", value:"HT212603");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2021-07-21-4");
  script_xref(name:"IAVA", value:"2021-A-0349-S");

  script_name(english:"macOS 10.14.x < 10.14.6 Mojave Security Update 2021-005 (HT212603)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS or Mac OS X security update or supplemental update that fixes multiple
vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 10.14.x prior to Mojave Security Update 2021-005 
Mojave. It is, therefore, affected by multiple vulnerabilities including the following:

  - A double free issue could be exploited which could lead to arbitrary code execution with kernel 
  privileges. This issue was addressed with improved memory management. (CVE-2021-30703)

  - An issue could be exploited by tricking a user into opening a maliciously crafted file may lead to 
  unexpected application termination or arbitrary code execution. This issue was addressed by removing 
  the vulnerable code. (CVE-2021-30790)

  - An input validation issue could be exploited which could lead to arbitrary code execution with kernel 
  privileges. This issue was addressed with input validation. (CVE-2021-30805)

Note that Nessus has not tested for this issue but has instead relied only on the operating system's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT212603");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 10.14.x < Mojave Security Update 2021-005 Mojave or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30805");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
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

include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();

var constraints = 
[
  { 'min_version' : '10.14.0', 
    'max_version' : '10.14.6',
    'fixed_build' : '18G9323',
    'fixed_display' : 'Mojave Security Update 2021-005 Mojave' 
  }
];

vcf::apple::macos::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_HOLE
);
