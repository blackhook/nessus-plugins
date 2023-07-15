#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139456);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/10");

  script_name(english:"Foxit PhantomPDF < 3.4 DoS (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote macOS host is affected by a DoS vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Foxit PhantomPDF installed on the remote macOS host is prior to 3.4. It is, therefore, affected by a
denial of service (DoS) vulnerability due to a null pointer dereference.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.foxitsoftware.com/support/security-bulletins.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a27a3e57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PhantomPDF version 3.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Based on vendor advisory analysis");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantompdf");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_foxit_phantompdf_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Foxit PhantomPDF");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('Host/local_checks_enabled');
os = get_kb_item('Host/MacOSX/Version');
if (empty_or_null(os)) audit(AUDIT_OS_NOT, 'Mac OS X');

app_info = vcf::get_app_info(app:'Foxit PhantomPDF');

constraints = [
  { 'max_version' : '3.3.0.0709', 'fixed_version' : '3.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
