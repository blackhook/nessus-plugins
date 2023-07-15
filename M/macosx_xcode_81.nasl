#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(94935);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/05");

  script_cve_id(
    "CVE-2015-3193",
    "CVE-2015-3194",
    "CVE-2015-6764",
    "CVE-2015-8027",
    "CVE-2016-0702",
    "CVE-2016-0705",
    "CVE-2016-0797",
    "CVE-2016-1669",
    "CVE-2016-2086",
    "CVE-2016-2216"
  );
  script_bugtraq_id(
    78207,
    78209,
    78623,
    83141,
    83282,
    83754,
    83763,
    90584
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-10-27-1");

  script_name(english:"Apple Xcode < 8.1 Node.js Multiple RCE (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"An IDE application installed on the remote macOS or Mac OS X host is affected by multiple remote code execution
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Xcode installed on the remote macOS or Mac OS X host is prior to 8.1. It is, therefore, affected
by multiple remote code execution vulnerabilities in the Node.js component of the Xcode Server. An unauthenticated,
remote attacker can exploit these vulnerabilities to cause a denial of service condition or the execution of arbitrary
code.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT207268");
  # http://lists.apple.com/archives/security-announce/2016/Oct/msg00005.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0f77052");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Xcode version 8.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0705");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:xcode");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'fixed_version' : '8.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
