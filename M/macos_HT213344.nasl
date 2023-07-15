#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164292);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/15");

  script_cve_id(
    "CVE-2022-0156",
    "CVE-2022-0158",
    "CVE-2022-26704",
    "CVE-2022-32781",
    "CVE-2022-32785",
    "CVE-2022-32786",
    "CVE-2022-32787",
    "CVE-2022-32797",
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
    "CVE-2022-32825",
    "CVE-2022-32826",
    "CVE-2022-32831",
    "CVE-2022-32832",
    "CVE-2022-32834",
    "CVE-2022-32838",
    "CVE-2022-32839",
    "CVE-2022-32843",
    "CVE-2022-32847",
    "CVE-2022-32848",
    "CVE-2022-32849",
    "CVE-2022-32851",
    "CVE-2022-32853",
    "CVE-2022-32857"
  );
  script_xref(name:"APPLE-SA", value:"HT213344");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2022-07-20");
  script_xref(name:"IAVA", value:"2022-A-0295-S");
  script_xref(name:"IAVA", value:"2022-A-0442-S");

  script_name(english:"macOS 11.x < 11.6.8 (HT213344)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS or Mac OS X security update or supplemental update that fixes multiple
vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 11.x prior to 11.6.8 Big Sur. It is, therefore, 
affected by multiple vulnerabilities :

  - An out-of-bounds write issue vulnerability may lead to arbitrary code execution. (CVE-2022-32787)

  - Exploitation of this vulnerability may lead to arbitrary code execution with kernel privileges. (CVE-2022-32812)

  - Exploitation of this vulnerability may lead to access of sensitive user information. (CVE-2022-32834) 

Note that Nessus has not tested for this issue but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-gb/HT213344");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 11.6.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26704");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-32839");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();
var constraints = [{ 'min_version' : '11.0', 'fixed_version' : '11.6.6', 'fixed_display' : 'macOS Big Sur 11.6.6' }];

vcf::apple::macos::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
