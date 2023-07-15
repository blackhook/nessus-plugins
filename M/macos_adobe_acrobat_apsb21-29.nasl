#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149381);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2021-21038",
    "CVE-2021-21044",
    "CVE-2021-21086",
    "CVE-2021-28550",
    "CVE-2021-28553",
    "CVE-2021-28555",
    "CVE-2021-28557",
    "CVE-2021-28558",
    "CVE-2021-28559",
    "CVE-2021-28560",
    "CVE-2021-28561",
    "CVE-2021-28562",
    "CVE-2021-28564",
    "CVE-2021-28565"
  );
  script_xref(name:"IAVA", value:"2021-A-0229-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"Adobe Acrobat <= 2017.011.30194 / 2020.001.30020 / 2021.001.20150 Multiple Vulnerabilities (APSB21-29) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote macOS host is a version prior or equal to 2017.011.30194,
2020.001.30020, or 2021.001.20150. It is, therefore, affected by multiple vulnerabilities.

  - Acrobat Reader DC versions versions 2020.013.20074 (and earlier), 2020.001.30018 (and earlier) and
    2017.011.30188 (and earlier) are affected by an Out-of-bounds Write vulnerability when parsing a crafted
    jpeg file. An unauthenticated attacker could leverage this vulnerability to achieve arbitrary code
    execution in the context of the current user. Exploitation of this issue requires user interaction in that
    a victim must open a malicious file. (CVE-2021-21038, CVE-2021-21044)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb21-29.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Acrobat version 2017.011.30194 / 2020.001.30020 / 2021.001.20150 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28565");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_acrobat_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Acrobat");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

get_kb_item_or_exit('Host/local_checks_enabled');
os = get_kb_item('Host/MacOSX/Version');
if (empty_or_null(os)) audit(AUDIT_OS_NOT, 'Mac OS X');

app_info = vcf::get_app_info(app:'Adobe Acrobat');

# vcf::adobe_reader::check_version_and_report will
# properly separate tracks when checking constraints.
# x.y.30zzz = DC Classic
# x.y.20zzz = DC Continuous
constraints = [
  { 'min_version' : '15.7', 'max_version' : '21.001.20150', 'fixed_version' : '21.001.20155' },
  { 'min_version' : '20.1', 'max_version' : '20.001.30020', 'fixed_version' : '20.001.30025' },
  { 'min_version' : '17.8', 'max_version' : '17.011.30194', 'fixed_version' : '17.011.30196' }
];
vcf::adobe_reader::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, max_segs:3);
