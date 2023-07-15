#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119842);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/13");

  script_cve_id(
    "CVE-2018-4421",
    "CVE-2018-4427",
    "CVE-2018-4431",
    "CVE-2018-4435",
    "CVE-2018-4447",
    "CVE-2018-4449",
    "CVE-2018-4450",
    "CVE-2018-4462",
    "CVE-2018-4465"
  );
  script_bugtraq_id(106760);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2018-12-05-2");

  script_name(english:"macOS 10.13.6 Multiple Vulnerabilities (Security Update 2018-003)");
  script_summary(english:"Checks for the presence of Security Update 2018-003 (APPLE-SA-2018-12-05-2).");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS security update that fixes
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running macOS 10.13.6 and is missing a security
update. It is therefore, affected by multiple vulnerabilities
affecting the following components :

  - AMD
  - Disk Images
  - IOHIDFamily
  - Kernel
  - WindowServer");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT209341");
  # https://lists.apple.com/archives/security-announce/2018/Dec/msg00001.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9fcc92ca");
  script_set_attribute(attribute:"solution", value:
"Install Security Update 2018-003 or later for 10.13.6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-4465");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/MacOSX/packages/boms");

  exit(0);
}

include('lists.inc');
include('vcf.inc');
include('vcf_extras_apple.inc');

app_info = vcf::apple::macos::get_app_info();

constraints = [
  { 'min_version' : '10.13', 'max_version' : '10.13.6', 'fixed_build': '17G4015', 'fixed_display' : '10.13.6 Security Update 2018-003' }
];
vcf::apple::macos::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
