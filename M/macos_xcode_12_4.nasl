#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158830);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/14");

  script_cve_id("CVE-2021-1800");
  script_xref(name:"APPLE-SA", value:"HT212153");

  script_name(english:"Apple Xcode < 12.4 access to arbitrary files (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"An IDE application installed on the remote macOS or Mac OS X host is affected by arbitrary file access.");
  script_set_attribute(attribute:"description", value:
"The version of Xcode running on the remote host is prior to 12.4. It is, Therefore, potentially affected by
arbitrary file access as referenced in the vendor advisory. A remote attacker can exploit this to read arbitrary
files and disclose sensitive information.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT212153");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Xcode version 12.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1800");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:xcode");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_xcode_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Apple Xcode");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('Host/local_checks_enabled');

var os = get_kb_item('Host/MacOSX/Version');
if (empty_or_null(os))
  audit(AUDIT_OS_NOT, 'macOS or Mac OS X');

var app_info = vcf::get_app_info(app:'Apple Xcode');

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { 'fixed_version' : '12.4' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
