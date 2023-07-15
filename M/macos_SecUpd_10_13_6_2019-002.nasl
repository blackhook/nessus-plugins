#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(123130);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/17");

  script_cve_id(
    "CVE-2018-12015",
    "CVE-2018-18311",
    "CVE-2018-18313",
    "CVE-2019-6207",
    "CVE-2019-8504",
    "CVE-2019-8510",
    "CVE-2019-8513",
    "CVE-2019-8520",
    "CVE-2019-8521",
    "CVE-2019-8522",
    "CVE-2019-8526",
    "CVE-2019-8527",
    "CVE-2019-8529",
    "CVE-2019-8555",
    "CVE-2019-8561",
    "CVE-2019-8564"
  );
  script_bugtraq_id(104423, 106072, 106145);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2019-3-25-2");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/05/08");

  script_name(english:"macOS 10.13.6 Multiple Vulnerabilities (Security Update 2019-002)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS security update that fixes
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running macOS 10.13.6 and is missing a security
update. It is therefore, affected by multiple vulnerabilities
including:

  - An application may be able to execute arbitrary code with kernel
    privileges. (CVE-2019-8529)

  - A local user may be able to read kernel memory. (CVE-2019-8504)

  - A malicious application may be able to determine kernel memory
    layout. (CVE-2019-6207, CVE-2019-8510)

  - 802.1X
  - DiskArbitration
  - Feedback Assistant
  - IOKit
  - IOKit SCSI
  - Kernel
  - PackageKit
  - Perl
  - Security
  - Time Machine
  - Wi-Fi");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT209600");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT209635");
  # https://lists.apple.com/archives/security-announce/2019/Mar/msg00001.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?71533e9d");
  script_set_attribute(attribute:"solution", value:
"Install Security Update 2019-002 or later for 10.13.6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8527");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-18311");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mac OS X TimeMachine (tmdiagnose) Command Injection Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/MacOSX/packages/boms");

  exit(0);
}

include('lists.inc');
include('vcf.inc');
include('vcf_extras_apple.inc');

app_info = vcf::apple::macos::get_app_info();

constraints = [
  { 'min_version' : '10.13', 'max_version' : '10.13.6', 'fixed_build': '17G6029', 'fixed_display' : '10.13.6 Security Update 2019-002' }
];
vcf::apple::macos::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
