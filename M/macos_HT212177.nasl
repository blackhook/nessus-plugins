#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(146427);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/18");

  script_cve_id("CVE-2021-1805", "CVE-2021-1806", "CVE-2021-3156");
  script_xref(name:"APPLE-SA", value:"HT212177");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2021-02-09-1");
  script_xref(name:"IAVA", value:"2021-A-0085-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/27");

  script_name(english:"macOS 10.14.x < 10.14.6 Security Update 2021-002 / 10.15.x < 10.15.7 Supplemental Update / macOS 11.x < 11.2.1 (HT212177)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS security update.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 10.14.x prior to 10.14.6 Security Update 2021-002
Mojave, 10.15.x prior to 10.15.7 Supplemental Update Catalina, or 11.x prior to 11.2.1 Big Sur. It is, therefore,
affected by multiple vulnerabilities, including the following:

  - An out-of-bounds-write vulnerability caused by insufficient input validation that allows an application
    to execute arbitrary code with kernel privileges. (CVE-2021-1805)

  - A race condition due to insufficient validation that allows an application to execute arbitrary code with
    kernel privileges. (CVE-2021-1806)

  - A local privilege elevation vulnerability in sudo caused by a heap-based buffer overflow. (CVE-2021-3156)


Note that Nessus has not tested for this issue but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT212177");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 10.14.6 Security Update 2021-002 / 10.15.7 Supplemental Update / macOS 11.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1805");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3156");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sudo Heap-Based Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_apple.inc');

app_info = vcf::apple::macos::get_app_info();

constraints = [
  { 'max_version' : '10.14.6', 'min_version' : '10.14', 'fixed_build': '18G8022', 'fixed_display' : '10.14.6 Security Update 2021-002 Mojave' },
  { 'max_version' : '10.15.7', 'min_version' : '10.15', 'fixed_build': '19H524', 'fixed_display' : '10.15.7 Supplemental Update Catalina' },
  { 'min_version' : '11.0', 'fixed_version' : '11.2.1', 'fixed_display' : 'macOS Big Sur 11.2.1' }
];

vcf::apple::macos::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
