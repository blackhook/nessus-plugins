#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174615);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2020-13954");
  script_xref(name:"IAVA", value:"2023-A-0210");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle WebCenter Sites (Apr 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 12.2.1.4.0 version of WebCenter Sites installed on the remote host is affected by multiple vulnerabilities as
referenced in the April 2023 CPU advisory.

  - Vulnerability in the Oracle WebCenter Sites product of Oracle Fusion Middleware (component: Samples (Apache CXF)). 
    The supported version that is affected is 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated 
    attacker with network access via HTTP to compromise Oracle WebCenter Sites. Successful attacks require human 
    interaction from a person other than the attacker and while the vulnerability is in Oracle WebCenter Sites, 
    attacks may significantly impact additional products (scope change). Successful attacks of this vulnerability 
    can result in unauthorized update, insert or delete access to some of Oracle WebCenter Sites accessible 
    data as well as unauthorized read access to a subset of Oracle WebCenter Sites accessible data.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2023 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13954");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:webcenter_sites");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_webcenter_sites_installed.nbin", "oracle_enum_products_win.nbin");
  script_require_keys("SMB/WebCenter_Sites/Installed");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_oracle_webcenter_sites.inc');

var app_info = vcf::oracle_webcenter_sites::get_app_info();

var constraints = [
  { 'min_version' : '12.2.1.4.0', 'fixed_version' : '12.2.1.4.230418' }
];

vcf::oracle_webcenter_sites::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
