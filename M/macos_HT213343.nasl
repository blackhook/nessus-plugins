##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163394);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/15");

  script_cve_id(
    "CVE-2021-4136",
    "CVE-2021-4166",
    "CVE-2021-4173",
    "CVE-2021-4187",
    "CVE-2021-4192",
    "CVE-2021-4193",
    "CVE-2022-0128",
    "CVE-2022-26704",
    "CVE-2022-32781",
    "CVE-2022-32785",
    "CVE-2022-32786",
    "CVE-2022-32787",
    "CVE-2022-32797",
    "CVE-2022-32799",
    "CVE-2022-32800",
    "CVE-2022-32805",
    "CVE-2022-32807",
    "CVE-2022-32811",
    "CVE-2022-32812",
    "CVE-2022-32813",
    "CVE-2022-32815",
    "CVE-2022-32819",
    "CVE-2022-32820",
    "CVE-2022-32823",
    "CVE-2022-32826",
    "CVE-2022-32831",
    "CVE-2022-32832",
    "CVE-2022-32834",
    "CVE-2022-32838",
    "CVE-2022-32839",
    "CVE-2022-32842",
    "CVE-2022-32843",
    "CVE-2022-32847",
    "CVE-2022-32849",
    "CVE-2022-32851",
    "CVE-2022-32853",
    "CVE-2022-32857"
  );
  script_xref(name:"APPLE-SA", value:"HT213343");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2022-07-20");
  script_xref(name:"IAVA", value:"2022-A-0294-S");
  script_xref(name:"IAVA", value:"2022-A-0442-S");

  script_name(english:"macOS 10.15.x < Catalina Security Update 2022-005 Catalina (HT213343)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS or Mac OS X security update or supplemental update that fixes multiple
vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 0.0.x prior to Catalina Security Update 2022-005
Catalina. It is, therefore, affected by multiple vulnerabilities :

  - vim is vulnerable to Heap-based Buffer Overflow (CVE-2021-4136)

  - vim is vulnerable to Out-of-bounds Read (CVE-2021-4166, CVE-2021-4193, CVE-2022-0128)

  - vim is vulnerable to Use After Free (CVE-2021-4173, CVE-2021-4187, CVE-2021-4192)

  - A validation issue existed in the handling of symlinks and was addressed with improved validation of
    symlinks. This issue is fixed in macOS Monterey 12.4. An app may be able to gain elevated privileges.
    (CVE-2022-26704)

  - An issue in FaceTime was addressed by enabling hardened runtime. (CVE-2022-32781)

  - A null pointer dereference in ImageIO was addressed with improved validation. (CVE-2022-32785)

  - An issue in the handling of environment variables in PackageKitwas addressed with improved validation.
    (CVE-2022-32786)

  - An out-of-bounds write issue in the ICU library was addressed with improved bounds checking.
    (CVE-2022-32787, CVE-2022-32843)

  - Several issues in AppleScript  were addressed with improved checks.
    (CVE-2022-32797, CVE-2022-32800, CVE-2022-32847)

  - An out-of-bounds read issue in SMB was addressed with improved bounds checking. (CVE-2022-32799)

  - An issue in the Calendar app was addressed with improved handling of caches. (CVE-2022-32805)

  - An issue in Spindump addressed with improved file handling. (CVE-2022-32807)

  - A memory corruption vulnerability in the Intel graphics driver was addressed with improved locking.
    (CVE-2022-32811)

  - Issues in the kernel were addressed with improved memory handling. (CVE-2022-32812, CVE-2022-32813, CVE-2022-32815,
    CVE-2022-32832)

  - A logic issue was addressed with improved state management. (CVE-2022-32819, CVE-2022-32838)

  - An out-of-bounds write issue was addressed with improved input validation. (CVE-2022-32820)

  - A memory initialization in libxml2 issue was addressed with improved memory handling. (CVE-2022-32823)

  - An authorization issue in AppleMobileFileIntegrity was addressed with improved state management. (CVE-2022-32826)

  - An out-of-bounds read was addressed with improved bounds checking. (CVE-2022-32831)

  - An access issue was addressed with improvements to the sandbox. (CVE-2022-32834)

  - The issue was addressed with improved bounds checks. (CVE-2022-32839)

  - An out-of-bounds read issue in AppleScript was addressed with improved input validation. (CVE-2022-32842,
    CVE-2022-32851, CVE-2022-32853)

  - An information disclosure issue in the Calendar app was addressed by removing the vulnerable code.
    (CVE-2022-32849)

  - This issue was addressed by using HTTPS when sending information over the network. (CVE-2022-32857)

Note that Nessus has not tested for this issue but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213343");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 10.15.x < Catalina Security Update 2022-005 Catalina or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26704");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-32839");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();

var constraints = [
  {
    'min_version' : '10.15',
    'max_version' : '10.15.7',
    'fixed_build' : '19H2026',
    'fixed_display' : 'Catalina 10.15.7 Security Update 2022-005'
  }
];
vcf::apple::macos::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
