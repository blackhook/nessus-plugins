#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156855);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2021-45105");
  script_xref(name:"IAVA", value:"2022-A-0029");

  script_name(english:"Oracle WebCenter Portal DoS (Jan 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application server installed on the remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle WebCenter Portal installed on the remote host is missing a security patch from the January 2022
Critical Patch Update (CPU). It is, therefore, affected by a denial of service vulnerability in its bundled Log4j 
component. An unauthenticated, remote attacker could exploit this, by sending a specially crafted request, to cause a 
DoS condition on the application.

Note that Nessus has not attempted to exploit this issue but has instead relied only on the application's self-reported 
version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujan2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2022.html#AppendixFMW");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-45105");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:webcenter_portal");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_webcenter_portal_installed.nbin");
  script_require_keys("installed_sw/Oracle WebCenter Portal");

  exit(0);
}

include('vcf_extras_oracle_webcenter_portal.inc');

var app_info = vcf::oracle_webcenter_portal::get_app_info();

var constraints = [
  {'min_version' : '12.2.1.3', 'fixed_version' : '12.2.1.3.211221'},
  {'min_version' : '12.2.1.4', 'fixed_version' : '12.2.1.4.211222'}
];

vcf::oracle_webcenter_portal::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
