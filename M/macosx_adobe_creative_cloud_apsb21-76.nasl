##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(153459);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id("CVE-2021-28613");
  script_xref(name:"IAVA", value:"2021-A-0421-S");

  script_name(english:"Adobe Creative Cloud < 5.5 Arbitrary file system write (APSB21-76) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Creative Cloud instance installed on the remote host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Creative Cloud installed on the remote macOS host is prior to 5.5. It is, therefore, affected by a
vulnerability as referenced in the apsb21-76 advisory.

  - Adobe Creative Cloud Desktop Application version 5.4 (and earlier) is affected by a file handling
    vulnerability that could allow an attacker to arbitrarily overwrite a file. Exploitation of this issue
    requires local access, administrator privileges and user interaction. (CVE-2021-28613)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/379.html");
  # https://helpx.adobe.com/security/products/creative-cloud/apsb21-76.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d345a92d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Creative Cloud version 5.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:C/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28613");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(379);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:creative_cloud");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_creative_cloud_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Creative Cloud");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled'))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/MacOSX/Version'))
  audit(AUDIT_OS_NOT, 'macOS');

var app_info = vcf::get_app_info(app:'Creative Cloud');

var constraints = [
  { 'fixed_version' : '5.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
