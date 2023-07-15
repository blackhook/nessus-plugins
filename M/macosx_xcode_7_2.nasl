#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(87737);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/05");

  script_cve_id(
    "CVE-2015-7049",
    "CVE-2015-7056",
    "CVE-2015-7057",
    "CVE-2015-7082"
  );
  script_bugtraq_id(78727);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-12-08-6");

  script_name(english:"Apple Xcode < 7.2 Multiple Vulnerabilities (Mac OS X)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has an application installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Xcode installed on the remote Mac OS X host is prior to 7.2. It is, therefore, affected by
multiple vulnerabilities :

  - Multiple remote code execution vulnerabilities exist due to a flaw in the otools component that is
    triggered when handling Mach-O files. A remote attacker can exploit these vulnerabilities to execute
    arbitrary code. (CVE-2015-7049, CVE-2015-7057)

  - A flaw exists in the IDE SCM due to the .gitignore directive not being honored. An unauthenticated, remote
    attacker can exploit this to disclose sensitive information. (CVE-2015-7056)

  - A remote code execution vulnerability exists due to a flaw in git-remote-ext that is triggered when
    handling a specially crafted URL. An unauthenticated, remote attacker can exploit this to execute
    arbitrary code. (CVE-2015-7082)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT205642");
  # http://lists.apple.com/archives/security-announce/2015/Dec/msg00004.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3a57b3d5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Xcode version 7.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7082");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/09/23");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/05");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:apple:xcode");
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
  { 'fixed_version' : '7.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
