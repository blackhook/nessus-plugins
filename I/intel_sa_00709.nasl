##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164086);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id("CVE-2022-28697", "CVE-2022-30601", "CVE-2022-30944");
  script_xref(name:"IAVA", value:"2022-A-0327");

  script_name(english:"Intel Active Management Technology (AMT) Multiple Vulnerabilities (INTEL-SA-00709) (remote check)");

  script_set_attribute(attribute:"synopsis", value:
"The management engine on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Intel Management Engine on the remote host has Active Management Technology (AMT) enabled, and, according to its
self-reported version, is a version containing multiple vulnerabilities, including the following:

  - Insufficiently protected credentials for Intel(R) AMT and Intel(R) Standard Manageability may allow an 
    unauthenticated user to potentially enable information disclosure and escalation of privilege via network 
    access. (CVE-2022-30601)

  - Insufficiently protected credentials for Intel(R) AMT and Intel(R) Standard Manageability may allow a privileged 
    user to potentially enable information disclosure via local access. (CVE-2022-30944)

  - Improper access control in firmware for Intel(R) AMT and Intel(R) Standard Manageability may allow an 
    unauthenticated user to potentially enable escalation of privilege via physical access.(CVE-2022-28697)


Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00709.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5e4e51d");
  script_set_attribute(attribute:"solution", value:
"Contact your system OEM for updated firmware per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30601");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:intel:active_management_technology");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:intel:active_management_technology_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("intel_amt_remote_detect.nbin");
  script_require_keys("installed_sw/Intel Active Management Technology");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('installed_sw/Intel Active Management Technology');

var app = 'Intel Active Management Technology';
var app_info = vcf::combined_get_app_info(app:app);

# Paranoid because no fixed version
if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, app, app_info.version);

var constraints = [
  # latest AMT version at time of writing is 15.0
  { 'min_version' : '0.0',  'fixed_version' : '99.99' , 'fixed_display': 'See vendor advisory'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
