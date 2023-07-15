##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143478);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2020-27930", "CVE-2020-27932", "CVE-2020-27950");
  script_xref(name:"APPLE-SA", value:"HT211946");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2020-11-04");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"macOS 10.13.x < 10.13.6 Security Update 2020-006 / 10.14.x < 10.14.6 Security Update 2020-006 (HT211946)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS or Mac OS X security update or supplemental update that fixes multiple
vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 10.13.x prior to 10.13.6 Security Update 2020-006 High
Sierra, or 10.14.x prior to 10.14.6 Security Update 2020-006 Mojave. It is, therefore, affected by multiple
vulnerabilities :

  - Processing a maliciously crafted font may lead to arbitrary code execution. (CVE-2020-27930)

  - A malicious application may be able to execute arbitrary code with kernel privileges. (CVE-2020-27932)

  - A malicious application may be able to disclose kernel memory. (CVE-2020-27950)

Note that Nessus has not tested for this issue but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT211946");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 10.13.6 Security Update 2020-006 / 10.14.6 Security Update 2020-006 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27932");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_apple.inc');

app_info = vcf::apple::macos::get_app_info();

constraints = [
  { 'max_version' : '10.13.6', 'min_version' : '10.13', 'fixed_build': '17G14042', 'fixed_display' : '10.13.6 Security Update 2020-006' },
  { 'max_version' : '10.14.6', 'min_version' : '10.14', 'fixed_build': '18G6042', 'fixed_display' : '10.14.6 Security Update 2020-006' }
];
vcf::apple::macos::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
