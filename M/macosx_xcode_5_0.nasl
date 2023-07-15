#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(70093);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/05");

  script_cve_id("CVE-2013-0308");
  script_bugtraq_id(58148);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-09-18-3");

  script_name(english:"Apple Xcode < 5.0 (Mac OS X)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is prone to a man-in-the-middle attack.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has Apple Xcode prior to 5.0 installed. It, therefore, includes a version of git in which the
imap-send command reportedly does not verify that a server hostname matches the domain name in its X.509 certificate. A
man-in-the-middle attacker could leverage this vulnerability to spoof SSL servers via an arbitrary valid certificate.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5937");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Sep/msg00007.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/528719/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Xcode version 5.0 or later, available for OS X Mountain Lion 10.8.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0308");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:xcode");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

constraints = [
  { 'fixed_version' : '5.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
