#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173917);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/05");

  script_xref(name:"IAVA", value:"2022-A-0485-S");

  script_name(english:"Foxit PDF Editor for Mac < 11.1.4 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote macOS host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit PDF Editor for Mac application (previously named Foxit PhantomPDF for Mac) installed
on the remote macOS host is prior to 11.1.4. It is, therefore affected multiple vulnerabilities, including the following:

  - A null pointer dereference that could lead to a denial of service (DoS).

  - An out of bounds array read when parsing certain U3D files.

  - A null pointer dereference that could lead to a denial of service (DoS) vulnerability when parsing certain
    PDF files.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.foxit.com/support/security-bulletins.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PDF Editor for Mac version 11.1.4 or later");

  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the issues by Tenable.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantompdf");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_foxit_phantompdf_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Foxit PhantomPDF");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('Host/local_checks_enabled');

var os = get_kb_item('Host/MacOSX/Version');
if (empty_or_null(os)) audit(AUDIT_OS_NOT, 'Mac OS X');

var app_info = vcf::get_app_info(app:'Foxit PhantomPDF');

var constraints = [
  { 'max_version' : '11.1.3.0920', 'fixed_version' : '11.1.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
