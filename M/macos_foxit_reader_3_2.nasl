#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139663);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/18");

  script_name(english:"Foxit Reader 3.1.0.0111 < 3.2 Privilege Escalation (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote macOS host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Foxit Reader for Mac installed on the remote macOS host is 3.1.0.0111. It is, therefore, affected by a
privilege escalation vulnerability due to incorrect permission setting. An attacker could exploit this by modifying the
dynamic libraries in the Plugins directory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.foxitsoftware.com/support/security-bulletins.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a27a3e57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit Reader version 3.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Based on analysis of vendor advisory");  

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_foxit_reader_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Foxit Reader");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('Host/local_checks_enabled');
os = get_kb_item('Host/MacOSX/Version');
if (empty_or_null(os)) audit(AUDIT_OS_NOT, 'Mac OS X');

app_info = vcf::get_app_info(app:'Foxit Reader');

constraints = [
  { 'equal' : '3.1.0.0111', 'fixed_version' : '3.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
