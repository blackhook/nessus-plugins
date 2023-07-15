##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146589);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/25");

  script_cve_id("CVE-2020-35931");

  script_name(english:"Foxit Reader < 4.1 PDF Spoofing (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote macOS host is affected by a PDF spoofing vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Foxit Reader for Mac installed on the remote macOS host is prior to 4.1.3. It is, therefore,
affected by a PDF spoofing vulnerability. An Evil Annotation Attack may deliver incorrect validation results when
validating certain certified PDF files whose visible content was significantly altered. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.foxitsoftware.com/support/security-bulletins.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a27a3e57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit Reader version 4.1.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-35931");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'max_version' : '4.1.1.1123', 'fixed_version' : '4.1.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
