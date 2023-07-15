#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153438);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id(
    "CVE-2021-39820",
    "CVE-2021-39821",
    "CVE-2021-39822",
    "CVE-2021-40727"
  );
  script_xref(name:"IAVA", value:"2021-A-0419-S");

  script_name(english:"Adobe InDesign <= 16.3 Multiple Arbitrary Code Execution Vulnerabilities (APSB21-73) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by multiple arbitrary code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe InDesign installed on the remote macOS host is prior or equal to 16.3. It is, therefore,
affected by multiple arbitrary code execution vulnerabilities, as follows:

  - Accessing a memory location after the end of the buffer allows an unauthenticated, remote attacker to
    execute arbitrary code. (CVE-2021-39820)

  - Out-of-bounds-reads allows a local attacker to execute arbitrary code. (CVE-2021-39821, CVE-2021-39822)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/indesign/apsb21-73.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a1533c3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe InDesign version 16.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39820");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:indesign");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_indesign_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe InDesign");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/MacOSX/Version')) audit(AUDIT_OS_NOT, 'macOS');

var app = 'Adobe InDesign';
var app_info = vcf::get_app_info(app:app);

var constraints = [
  { 'fixed_version' : '16.3.3', 'fixed_display' : '16.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

