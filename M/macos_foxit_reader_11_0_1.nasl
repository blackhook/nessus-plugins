#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152210);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2021-21831",
    "CVE-2021-21893",
    "CVE-2021-34832",
    "CVE-2021-34846"
  );
  script_xref(name:"IAVA", value:"2021-A-0357-S");

  script_name(english:"Foxit PDF Reader < 11.0.1 Multiple Vulnerabilities (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Foxit PDF Reader for Mac installed on the remote macOS host is prior to 11.0.1. It is, therefore,
affected by multiple vulnerabilities:

  - Multiple remote code execution vulnerabilities exist in Foxit PDF Reader due to use-after-free errors when
    handling certain Javascripts. An unauthenticated, remote attacker can exploit these, by convincing a user
    to open a malicious file or visit a malicious site with the browser plugin extension enabled, to cause
    execute arbitrary code in the context of the current user. (CVE-2021-21831, CVE-2021-34832)

  - A remote code execution vulnerability exists in Foxit PDF Reader due to a use-after-free error when
    handling certain form elements. An unauthenticated, remote attacker can exploit this, by convincing a user
    to open a malicious file or visit a malicious site with the browser plugin extension enabled, to execute
    arbitrary code in the context of the current user. (CVE-2021-21893)

  - A remote code execution vulnerability exists in Foxit PDF Reader due to a use-after-free error in handling
    certain annotation objects. An unauthenticated, remote attacker can exploit this, by convincing a user to
    open a malicious file or visit a malicious site with the browser plugin extension enabled, to execute
    arbitrary code in the context of the current user. (CVE-2021-34846)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.foxitsoftware.com/support/security-bulletins.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a27a3e57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit Reader version 11.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34846");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-21893");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_reader");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_foxit_reader_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Foxit Reader");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('Host/local_checks_enabled');

var os = get_kb_item('Host/MacOSX/Version');
if (empty_or_null(os)) audit(AUDIT_OS_NOT, 'Mac OS X');

var app_info = vcf::get_app_info(app:'Foxit Reader');

var constraints = [
  { 'max_version' : '11.0.0.0510', 'fixed_version' : '11.0.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
