#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160161);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/30");

  script_cve_id("CVE-2022-23305");
  script_xref(name:"IAVA", value:"2022-A-0171");

  script_name(english:"Oracle Tuxedo RCE (Apr 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application server installed on the remote host is affected by a remote code execution vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tuxedo installed on the remote host is missing a security patch. It is, therefore affected
by a remote code execution vulnerability in the bundled Apache Log4J component.  Successful exploitation of
this vulnerability allow an unauthenticated attacker with network access via HTTP takeover of Oracle Tuxedo.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23305");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:tuxedo");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_tuxedo_installed.nbin");
  script_require_keys("installed_sw/Oracle Tuxedo");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::get_app_info(app:'Oracle Tuxedo');

var constraints = [
  {'version_regex':"^12\.2\.2\.0($|\.|_)", 'rp_fix': 87}
];

vcf::oracle_tuxedo::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
