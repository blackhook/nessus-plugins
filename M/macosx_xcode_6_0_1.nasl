#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(77863);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/05");

  script_cve_id("CVE-2014-0032");
  script_bugtraq_id(65434);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2014-09-17-7");

  script_name(english:"Apple Xcode < 6.0.1 (Mac OS X)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Apple Xcode prior to 6.0.1 installed. It is, therefore, affected by a denial
of service vulnerability in the bundled Subversion component. The 'get_resource' function in 'repos.c' in the
'mod_dav_svn' module allows remote attackers to cause a denial of service when the 'SVNListParentPath' option is
enabled.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6444");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/533477/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Xcode version 6.0.1 or later, which is available for OS X 10.9.4 (Mavericks) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0032");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:xcode");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'fixed_version' : '6.0.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
