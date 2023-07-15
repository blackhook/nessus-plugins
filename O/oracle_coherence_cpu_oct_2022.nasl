#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166378);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/24");

  script_cve_id("CVE-2022-24823");
  script_xref(name:"IAVA", value:"2022-A-0431");

  script_name(english:"Oracle Coherence Unauthorized Access (Oct 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an unauthorized access vulnerability.");
  script_set_attribute(attribute:"description", value:
"The 12.2.1.4.0 and 14.1.1.0.0 versions of Coherence installed on the remote host are affected
by an unauthorized access vulnerability as referenced in the Oct 2022 CPU advisory. This easily exploitable 
vulnerability allows low privileged attacker with logon to the infrastructure where Oracle Coherence executes to 
compromise Oracle Coherence. Successful attacks of this vulnerability can result in unauthorized access to critical 
data or complete access to all Oracle Coherence accessible data. 

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuoct2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the Oct 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24823");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:coherence");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_coherence_installed.nbin");
  script_require_keys("installed_sw/Oracle Coherence");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle Coherence');

var constraints = [
  {'min_version': '12.2.1.4.0', 'fixed_version': '12.2.1.4.15'},
  {'min_version': '14.1.1.0.0', 'fixed_version': '14.1.1.0.11'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);
