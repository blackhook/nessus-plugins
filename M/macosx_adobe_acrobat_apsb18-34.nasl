#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117597);
  script_version("1.7");
  script_cvs_date("Date: 2019/04/19 10:12:36");

  script_cve_id(
    "CVE-2018-12848",
    "CVE-2018-12849",
    "CVE-2018-12850",
    "CVE-2018-12801",
    "CVE-2018-12840",
    "CVE-2018-12778",
    "CVE-2018-12775"
  );

  script_name(english:"Adobe Acrobat <= 15.006.30448 / 17.011.30099 / 18.011.20058 Multiple Vulnerabilities (APSB18-34) (macOS)");
  script_summary(english:"Checks the version of Adobe Acrobat.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat installed on the remote host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote macOS or Mac OS
host is a version prior or equal to 15.006.30448, 17.011.30099, or
18.011.20058. It is, therefore, affected by multiple vulnerabilities.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb18-34.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Acrobat 15.006.30452 / 17.011.30102 / 18.011.20063 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12848");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_acrobat_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Acrobat");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

get_kb_item_or_exit("Host/local_checks_enabled");
os = get_kb_item("Host/MacOSX/Version");
if (empty_or_null(os)) audit(AUDIT_OS_NOT, "Mac OS X");

app_info = vcf::get_app_info(app:"Adobe Acrobat");

  constraints = [
    { "min_version" : "15.6", "max_version":"15.006.30448", "fixed_version" : "15.006.30452" },
    { "min_version" : "17.8", "max_version":"17.011.30099", "fixed_version" : "17.011.30102" },
    { "min_version" : "18.8", "max_version":"18.011.20058", "fixed_version" : "18.011.20063" }
  ];
vcf::adobe_reader::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, max_segs:3);
