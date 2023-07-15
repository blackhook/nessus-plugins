#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176673);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/06");

  script_cve_id("CVE-2023-2255");
  script_xref(name:"IAVB", value:"2023-B-0037");

  script_name(english:"LibreOffice 7.4 < 7.4.7 / 7.5 < 7.5.3 Array Index UnderFlow (Windows)");

  script_set_attribute(attribute:"synopsis", value:
"An array index underFlow vulnerability exist in Document Foundation LibreOffice versions prior to 7.2.7 or 7.3.3.");
  script_set_attribute(attribute:"description", value:
"Improper access control in editor components of The Document Foundation LibreOffice allowed an attacker to craft a
document that would cause external links to be loaded without prompt. In the affected versions of LibreOffice documents
that used 'floating frames' linked to external files, would load the contents of those frames without prompting the
user for permission to do so. This was inconsistent with the treatment of other linked content in LibreOffice. This
issue affects: The Document Foundation LibreOffice 7.4 versions prior to 7.4.7; 7.5 versions prior to 7.5.3.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.libreoffice.org/about-us/security/advisories/CVE-2023-2255");
  script_set_attribute(attribute:"solution", value:
"Upgrade to LibreOffice version 7.4.7, 7.5.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2255");

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
  {'min_version':'7.4', 'fixed_version':'7.4.7'},
  {'min_version':'7.5', 'fixed_version':'7.5.3'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
