#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(82713);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/05");

  script_cve_id("CVE-2015-1149");
  script_bugtraq_id(73987, 73988);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-04-08-5");

  script_name(english:"Apple Xcode < 6.3 (Mac OS X)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has an application installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Xcode installed on the remote Mac OS X host is prior to 6.3. It is, therefore, affected by the
multiple vulnerabilities :

  - A stack allocation issue in Clang allows an attacker to bypass stack guards. (BID 73987)

  - An integer overflow issue in the Swift simulator leads to conversions returning unexpected values. An
    attacker can exploit this to cause a denial of service or to possibly execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT204663");
  # http://lists.apple.com/archives/security-announce/2015/Apr/msg00004.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4194297c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Xcode version 6.3, which is available for OS X 10.9.4 (Mavericks) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-1149");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:xcode");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'fixed_version' : '6.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
