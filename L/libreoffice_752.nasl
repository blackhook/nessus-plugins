#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176672);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/08");

  script_cve_id("CVE-2023-0950");
  script_xref(name:"IAVB", value:"2023-B-0037");

  script_name(english:"LibreOffice 7.4 < 7.4.6 / 7.5 < 7.5.2 Array Index UnderFlow (Windows)");

  script_set_attribute(attribute:"synopsis", value:
"An array index underFlow vulnerability exist in Document Foundation LibreOffice versions prior to 7.2.7 or 7.3.3.");
  script_set_attribute(attribute:"description", value:
"Improper Validation of Array Index vulnerability in the spreadsheet component of The Document Foundation LibreOffice
allows an attacker to craft a spreadsheet document that will cause an array index underflow when loaded. In the affected
versions of LibreOffice certain malformed spreadsheet formulas, such as AGGREGATE, could be created with less parameters
passed to the formula interpreter than it expected, leading to an array index underflow, in which case there is a risk
that arbitrary code could be executed. This issue affects: The Document Foundation LibreOffice 7.4 versions prior to
7.4.6; 7.5 versions prior to 7.5.1.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.libreoffice.org/about-us/security/advisories/CVE-2023-0950");
  script_set_attribute(attribute:"solution", value:
"Upgrade to LibreOffice version 7.4.6, 7.5.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0950");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("libreoffice_installed.nasl");
  script_require_keys("installed_sw/LibreOffice", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'LibreOffice');

var constraints = [
  {'min_version':'7.4', 'fixed_version':'7.4.6'},
  {'min_version':'7.5', 'fixed_version':'7.5.2'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
