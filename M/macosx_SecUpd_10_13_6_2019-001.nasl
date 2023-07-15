#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(121392);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/24");

  script_cve_id(
    "CVE-2018-4452",
    "CVE-2018-4467",
    "CVE-2019-6200",
    "CVE-2019-6202",
    "CVE-2019-6205",
    "CVE-2019-6208",
    "CVE-2019-6209",
    "CVE-2019-6210",
    "CVE-2019-6213",
    "CVE-2019-6214",
    "CVE-2019-6218",
    "CVE-2019-6220",
    "CVE-2019-6221",
    "CVE-2019-6224",
    "CVE-2019-6225",
    "CVE-2019-6230",
    "CVE-2019-6231"
  );
  script_bugtraq_id(106693, 106694);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2019-1-22-2");

  script_name(english:"macOS 10.13.6 Multiple Vulnerabilities (Security Update 2019-001)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS security update that fixes
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running macOS 10.13.6 and is missing a security
update. It is therefore, affected by multiple vulnerabilities in 
the following components:

  - Bluetooth
  - Core Media
  - CoreAnimation
  - FaceTime
  - Hypervisor
  - Intel Graphics Driver
  - IOKit
  - Kernel
  - libxpc
  - QuartzCore");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT209446");
  # https://lists.apple.com/archives/security-announce/2019/Jan/msg00001.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a77b9bea");
  script_set_attribute(attribute:"solution", value:
"Install Security Update 2019-001 or later for 10.13.6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6218");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-6224");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/MacOSX/packages/boms");

  exit(0);
}

include('lists.inc');
include('vcf.inc');
include('vcf_extras_apple.inc');

app_info = vcf::apple::macos::get_app_info();

constraints = [
  { 'min_version' : '10.13', 'max_version' : '10.13.6', 'fixed_build': '17G5019', 'fixed_display' : '10.13.6 Security Update 2019-001' }
];
vcf::apple::macos::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
