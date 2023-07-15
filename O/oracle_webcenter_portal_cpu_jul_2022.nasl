##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163288);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/30");

  script_cve_id("CVE-2021-39139");
  script_xref(name:"IAVA", value:"2022-A-0285");

  script_name(english:"Oracle WebCenter Portal RCE (Jul 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application server installed on the remote host is affected by a remote code execution vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Oracle WebCenter Portal installed on the remote host is missing a security patch from the July 2022
Critical Patch Update (CPU). It is, therefore, affected a remote code execution vulnerability:

 - Vulnerability in the Oracle WebCenter Portal product of Oracle Fusion Middleware (component: Security
   Framework (XStream)). Supported versions that are affected are 12.2.1.3.0 and 12.2.1.4.0. Easily
   exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle
   WebCenter Portal. Successful attacks of this vulnerability can result in takeover of Oracle WebCenter
   Portal. (CVE-2021-39139)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujul2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39139");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:webcenter_portal");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_webcenter_portal_installed.nbin");
  script_require_keys("installed_sw/Oracle WebCenter Portal");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_oracle_webcenter_portal.inc');

var app_info = vcf::oracle_webcenter_portal::get_app_info();

var constraints = [
  { 'min_version' : '12.2.1.3.0', 'fixed_version' : '12.2.1.3.220602' },
  { 'min_version' : '12.2.1.4.0', 'fixed_version' : '12.2.1.4.220602' }
];

vcf::oracle_webcenter_portal::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
