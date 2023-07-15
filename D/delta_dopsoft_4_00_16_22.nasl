#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173055);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/22");

  script_cve_id("CVE-2023-0123", "CVE-2023-0124");

  script_name(english:"Delta DOPSoft <= 4.00.16.22 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"Delta DOPSoft installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Delta DOPSoft installed on the remote host is prior to or equal to 4.00.16.22. It is, therefore, affected
by multiple vulnerabilities as referenced in the CISA ICSA-23-031-01 advisory.

  - Delta Electronics DOPSoft versions 4.00.16.22 and prior are vulnerable to a stack-based buffer overflow,
    which could allow an attacker to remotely execute arbitrary code when a malformed file is introduced to
    the software. (CVE-2023-0123)

  - Delta Electronics DOPSoft versions 4.00.16.22 and prior are vulnerable to an out-of-bounds write, which
    could allow an attacker to remotely execute arbitrary code when a malformed file is introduced to the
    software. (CVE-2023-0124)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.cisa.gov/uscert/ics/advisories/icsa-23-031-01");
  script_set_attribute(attribute:"solution", value:
"Delta Electronics released version 1.3.0 of DIAScreen and recommends users to use DIAScreen
instead of DOPSoft.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0124");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:deltaww:dopsoft");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("delta_dopsoft_win_installed.nbin");
  script_require_keys("installed_sw/Delta DOPSoft");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Delta DOPSoft', win_local:TRUE);

app_info.display_version = app_info.version + " (file version)";

# After installing the package DELTA_IA-HMI_DOPSoft-2-00-07-04_SW_TC-SC-EN-SP_20171214,
# Files are installed to C:\Program Files (x86)\Delta Industrial Automation\DOPSoft 2.00.07\
# and the DOPSoft.exe has a file version of 4.0.7.4 (not 2.x)
# 2.00.07 file version is 4.0.7.4
var constraints = [
  { 'max_version': '4.00.16.22', 'fixed_display':'Migrate to DIAScreen in DIAStudio v1.3.0 or later.'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
