#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(103359);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/05");

  script_cve_id(
    "CVE-2017-7076",
    "CVE-2017-7134",
    "CVE-2017-7135",
    "CVE-2017-7136",
    "CVE-2017-7137",
    "CVE-2017-9800",
    "CVE-2017-1000117"
  );
  script_bugtraq_id(100259, 100283, 100894);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2017-09-19-3");

  script_name(english:"Apple Xcode < 9.0 Multiple RCE (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"An IDE application installed on the remote macOS or Mac OS X host is affected by multiple remote code execution
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Xcode installed on the remote macOS or Mac OS X host is prior to 9.0. It is, therefore, affected
by multiple remote code execution vulnerabilities in the git, Id64, and subversion components. An unauthenticated,
remote attacker can exploit these vulnerabilities to cause execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT208103");
  # https://lists.apple.com/archives/security-announce/2017/Sep/msg00001.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f9703a45");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Xcode version 9.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9800");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Malicious Git HTTP Server For CVE-2017-1000117');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:xcode");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_xcode_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Apple Xcode");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('Host/local_checks_enabled');

os = get_kb_item('Host/MacOSX/Version');
if (empty_or_null(os))
  audit(AUDIT_OS_NOT, 'macOS or Mac OS X');

app_info = vcf::get_app_info(app:'Apple Xcode');

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'fixed_version' : '9.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
