#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130967);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id(
    "CVE-2017-7152",
    "CVE-2018-12152",
    "CVE-2018-12153",
    "CVE-2018-12154",
    "CVE-2019-8509",
    "CVE-2019-8592",
    "CVE-2019-8705",
    "CVE-2019-8706",
    "CVE-2019-8708",
    "CVE-2019-8709",
    "CVE-2019-8715",
    "CVE-2019-8716",
    "CVE-2019-8717",
    "CVE-2019-8736",
    "CVE-2019-8737",
    "CVE-2019-8744",
    "CVE-2019-8745",
    "CVE-2019-8746",
    "CVE-2019-8748",
    "CVE-2019-8749",
    "CVE-2019-8750",
    "CVE-2019-8754",
    "CVE-2019-8756",
    "CVE-2019-8759",
    "CVE-2019-8761",
    "CVE-2019-8767",
    "CVE-2019-8772",
    "CVE-2019-8784",
    "CVE-2019-8785",
    "CVE-2019-8786",
    "CVE-2019-8787",
    "CVE-2019-8788",
    "CVE-2019-8789",
    "CVE-2019-8794",
    "CVE-2019-8797",
    "CVE-2019-8798",
    "CVE-2019-8801",
    "CVE-2019-8802",
    "CVE-2019-8803",
    "CVE-2019-8805",
    "CVE-2019-8807",
    "CVE-2019-8817",
    "CVE-2019-8824",
    "CVE-2019-8825",
    "CVE-2019-8829",
    "CVE-2019-8831",
    "CVE-2019-8850",
    "CVE-2019-8858",
    "CVE-2019-11041",
    "CVE-2019-11042",
    "CVE-2019-15126"
  );
  script_bugtraq_id(103136, 105582);
  script_xref(name:"APPLE-SA", value:"HT210722");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2019-10-29");

  script_name(english:"macOS 10.15.x < 10.15.1 / 10.14.x < 10.14.6 Security Update 2019-001 / 10.13.x < 10.13.6 Security Update 2019-006");
  script_summary(english:"Checks the version of macOS or Mac OS X.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS or Mac OS X security update that fixes multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS or Mac OS X that is 10.15.x prior to 10.15.1, 10.14.x prior to 10.14.6 
security update 2019-001, 10.13.x prior to 10.13.6 security update 2019-006. It is, therefore, affected by multiple 
vulnerabilities :

  - An out-of-bounds read error exists in the accounts component due to improper input validation. A remote
    attacker can exploit this, to disclose memory contents. (CVE-2019-8787)

  - A security bypass vulnerability exists in the App Store component due to an improper state management
    implementation. A local attacker can exploit this, to login to the account of a previously logged in user
    without valid credentials. (CVE-2019-8803)

  - An out-of-bounds read error exists in the IOGraphics component due to improper bounds checking. A local
    attacker can exploit this, to cause unexpected system termination or to read kernel memory. 
    (CVE-2019-8759)

Note that Nessus has not tested for this issue but has instead relied only on the operating system's self-reported
version number.");
  # https://support.apple.com/en-us/HT210722
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?39d6c45e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 10.15.1 / 10.14.6 security update 2019-001 / 10.13.6 security update 2019-006 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8716");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/OS");

  exit(0);
}

include('lists.inc');
include('vcf.inc');
include('vcf_extras_apple.inc');

app_info = vcf::apple::macos::get_app_info();

constraints = [
  { 'min_version': '10.13', 'max_version': '10.13.6', 'fixed_build': '17G9016', 'fixed_display': '10.13.6 Security Update 2019-006' },
  { 'min_version': '10.14', 'max_version': '10.14.6', 'fixed_build': '18G1012', 'fixed_display': '10.14.6 Security Update 2019-001' },
  { 'min_version': '10.15', 'fixed_version': '10.15.1' }
];

vcf::apple::macos::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
