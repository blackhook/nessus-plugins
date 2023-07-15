#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(91262);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/05");

  script_cve_id("CVE-2016-2315", "CVE-2016-2324");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-05-03-1");

  script_name(english:"Apple Xcode < 7.3.1 Multiple RCE (Mac OS X)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Xcode installed on the remote Mac OS X host is prior to 7.3.1. It is, therefore, affected by
multiple remote code execution vulnerabilities in the bundled version of Git due to overflow conditions in the
path_name() function in revision.c that are triggered when pushing or cloning a repository with a large filename or
containing a large number of nested trees. A remote attacker can exploit these issues to cause a heap-based buffer
overflow, resulting in the execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT206338");
  # https://lists.apple.com/archives/security-announce/2016/May/msg00000.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc7dc6f0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Xcode version 7.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2324");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/19");

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

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'fixed_version' : '7.3.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
