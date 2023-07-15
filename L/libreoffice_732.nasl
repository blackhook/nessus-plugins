##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163762);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id("CVE-2022-26305");
  script_xref(name:"IAVB", value:"2022-B-0024-S");

  script_name(english:"LibreOffice < 7.2.7 / 7.3.2 Improper Certificate Validation (Windows)");

  script_set_attribute(attribute:"synopsis", value:
"A input validation vulnerability exists in Document Foundation LibreOffice versions prior to 7.2.7 or 7.3.2.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the LibreOffice application running on the remote host is prior to 7.2.7 or 
7.3.2. It is, therefore, affected by an Improper Certificate Validation vulnerability where determining if a macro was 
signed by a trusted author was done by only matching the serial number and issuer string of the used certificate with 
that of a trusted certificate. This is not sufficient to verify that the macro was actually signed with the certificate.
An adversary could therefore create an arbitrary certificate with a serial number and an issuer string identical to a 
trusted certificate which LibreOffice would present as belonging to the trusted author, potentially leading to the user
to execute arbitrary code contained in macros improperly trusted (CVE-2022-26305)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.libreoffice.org/about-us/security/advisories/CVE-2022-26305
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d91e2728");
  script_set_attribute(attribute:"solution", value:
"Upgrade to LibreOffice version 7.2.7, 7.3.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26305");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("libreoffice_installed.nasl");
  script_require_keys("installed_sw/LibreOffice", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'LibreOffice');

var constraints = [
  {'min_version':'1.0', 'fixed_version':'7.2.7'},
  {'min_version':'7.3', 'fixed_version':'7.3.2'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);