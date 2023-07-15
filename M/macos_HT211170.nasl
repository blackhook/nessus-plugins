#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136930);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id(
    "CVE-2019-14868",
    "CVE-2019-20044",
    "CVE-2020-3878",
    "CVE-2020-3882",
    "CVE-2020-9771",
    "CVE-2020-9772",
    "CVE-2020-9788",
    "CVE-2020-9789",
    "CVE-2020-9790",
    "CVE-2020-9791",
    "CVE-2020-9792",
    "CVE-2020-9793",
    "CVE-2020-9794",
    "CVE-2020-9795",
    "CVE-2020-9797",
    "CVE-2020-9804",
    "CVE-2020-9808",
    "CVE-2020-9809",
    "CVE-2020-9811",
    "CVE-2020-9812",
    "CVE-2020-9813",
    "CVE-2020-9814",
    "CVE-2020-9815",
    "CVE-2020-9816",
    "CVE-2020-9817",
    "CVE-2020-9821",
    "CVE-2020-9822",
    "CVE-2020-9824",
    "CVE-2020-9825",
    "CVE-2020-9826",
    "CVE-2020-9827",
    "CVE-2020-9828",
    "CVE-2020-9830",
    "CVE-2020-9831",
    "CVE-2020-9832",
    "CVE-2020-9833",
    "CVE-2020-9834",
    "CVE-2020-9837",
    "CVE-2020-9839",
    "CVE-2020-9841",
    "CVE-2020-9842",
    "CVE-2020-9844",
    "CVE-2020-9847",
    "CVE-2020-9851",
    "CVE-2020-9852",
    "CVE-2020-9855",
    "CVE-2020-9856",
    "CVE-2020-9857"
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2020-05-18");
  script_xref(name:"APPLE-SA", value:"HT211170");
  script_xref(name:"IAVA", value:"2020-A-0227-S");

  script_name(english:"macOS 10.15.x < 10.15.5 / 10.14.x < 10.14.6 Security Update 2020-003 / 10.13.x < 10.13.6 Security Update 2020-003");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 10.15.x prior to 10.15.5, 10.13.x prior to 10.13.6
Security Update 2020-003, 10.14.x prior to 10.14.6 Security Update 2020-003. It is, therefore, affected by multiple
vulnerabilities:

  - In ksh version 20120801, a flaw was found in the way it
    evaluates certain environment variables. An attacker
    could use this flaw to override or bypass environment
    restrictions to execute shell commands. Services and
    applications that allow remote unauthenticated attackers
    to provide one of those environment variables could
    allow them to exploit this issue remotely.
    (CVE-2019-14868)

  - In Zsh before 5.8, attackers able to execute commands
    can regain privileges dropped by the --no-PRIVILEGED
    option. Zsh fails to overwrite the saved uid, so the
    original privileges can be restored by executing
    MODULE_PATH=/dir/with/module zmodload with a module that
    calls setuid(). (CVE-2019-20044)

  - An out-of-bounds read was addressed with improved input
    validation. This issue is fixed in iOS 13.3.1 and iPadOS
    13.3.1, macOS Catalina 10.15.3, tvOS 13.3.1, watchOS
    6.1.2. Processing a maliciously crafted image may lead
    to arbitrary code execution. (CVE-2020-3878)

Note that Nessus has not tested for this issue but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT211170");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 10.15.5 / 10.14.x < 10.14.6 Security Update 2020-003 / 10.13.x < 10.13.6 Security Update 2020-003 or
later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9852");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-9790");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Safari in Operator Side Effect Exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/OS");

  exit(0);
}

include('vcf.inc');
include('lists.inc');
include('vcf_extras_apple.inc'); 

app_info = vcf::apple::macos::get_app_info();

constraints = [
  { 'max_version' : '10.15.4', 'min_version' : '10.15', 'fixed_build' : '19F96', 'fixed_display' : 'macOS Catalina 10.15.5' },
  { 'max_version' : '10.13.6', 'min_version' : '10.13', 'fixed_build' : '17G13033', 'fixed_display' : '10.13.6 Security Update 2020-003' },
  { 'max_version' : '10.14.6', 'min_version' : '10.14', 'fixed_build' : '18G5033', 'fixed_display' : '10.14.6 Security Update 2020-003' }
];

vcf::apple::macos::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

