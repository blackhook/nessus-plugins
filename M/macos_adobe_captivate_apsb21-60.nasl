#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152697);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/13");

  script_cve_id("CVE-2021-36002");
  script_xref(name:"IAVA", value:"2021-A-0381");

  script_name(english:"Adobe Captivate <= 11.5.5 Privilege Escalation (APSB21-60)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Captivate installed on remote macOS or Mac OS X host is affected by privilege escalation vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Captivate installed on the remote macOS or Mac OS X host is 11.5.5 or prior. It is, therefore,
affected by privilege escalation vulnerability as referenced in the apsb21-69 advisory, due to the creation of a 
temporary file in a directory with incorrect permissions.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/captivate/apsb21-60.html");
  script_set_attribute(attribute:"solution", value:
"Apply the hotfix available in the vendor advisory, or upgrade Upgrade to Adobe Captivate to a version later than 15.5.5.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-36002");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(379);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:captivate");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_captivate_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Captivate");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

get_kb_item_or_exit('Host/MacOSX/Version');

var app_info = vcf::get_app_info(app:'Adobe Captivate');

# version showing after installing the app from the fix page https://helpx.adobe.com/captivate/kb/access-privilege-fix.html
var constraints = [
  {'fixed_version' : '11.5.6.684'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
