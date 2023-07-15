#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153436);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/04");

  script_cve_id("CVE-2021-39826", "CVE-2021-39827", "CVE-2021-39828");
  script_xref(name:"IAVA", value:"2021-A-0423");

  script_name(english:"Adobe Digital Editions <= 4.5.11.187646 Multiple Vulnerabilities (macOS) (APSB21-80)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Adobe Digital Editions version 4.5.11.187646 (and earlier) is affected by multiple vulnerabilities, as follows:

  - An OS command injection vulnerability that can be exploited by a local attacker to execute arbitrary
    code. (CVE-2021-39826)

  - An arbitrary file system write vulnerability that can be exploited by a local attacker. (CVE-2021-39827)

  - A privilege escalation vulnerability that can be exploited by a local attacker. (CVE-2021-39828)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://helpx.adobe.com/security/products/Digital-Editions/apsb21-80.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e229dead");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Digital Editions version 4.5.11.187658 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39826");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:digital_editions");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_digital_editions_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Digital Editions", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit("Host/MacOSX/Version");
get_kb_item_or_exit("Host/local_checks_enabled");

var app_info = vcf::get_app_info(app:'Adobe Digital Editions');

# making this paranoid until the detection fix is released
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var constraints = [
  { 'fixed_version':'4.5.11.187647', 'fixed_display' : '4.5.11.187658' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
