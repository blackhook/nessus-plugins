#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174742);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/26");

  script_cve_id(
    "CVE-2019-10172",
    "CVE-2020-28052",
    "CVE-2021-23926",
    "CVE-2021-36090",
    "CVE-2022-34169",
    "CVE-2023-21910"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Business Intelligence Enterprise Edition (Apr 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Business Intelligence Enterprise Edition (OBIEE) installed
on the remote host are affected by multiple vulnerabilities as referenced in the April 2023 CPU advisory.

  - A flaw was found in org.codehaus.jackson:jackson-mapper-asl:1.9.x libraries. XML external entity
    vulnerabilities similar CVE-2016-3720 also affects codehaus jackson-mapper-asl libraries but in different
    classes. (CVE-2019-10172)

  - An issue was discovered in Legion of the Bouncy Castle BC Java 1.65 and 1.66. The
    OpenBSDBCrypt.checkPassword utility method compared incorrect data when checking the password, allowing
    incorrect passwords to indicate they were matching with previously hashed ones that were different.
    (CVE-2020-28052)

  - The XML parsers used by XMLBeans up to version 2.6.0 did not set the properties needed to protect the user
    from malicious XML input. Vulnerabilities include possibilities for XML Entity Expansion attacks. Affects
    XMLBeans up to and including v2.6.0. (CVE-2021-23926)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-28052");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-23926");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_intelligence");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_business_intelligence_enterprise_edition_installed.nbin");
  script_require_keys("installed_sw/Oracle Business Intelligence Enterprise Edition");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle Business Intelligence Enterprise Edition');

var constraints = [
  {'min_version': '12.2.1.4.0', 'fixed_version': '12.2.1.4.230407', 'fixed_display': '12.2.1.4.230407 patch: 35268009'}
];

vcf::check_version_and_report(app_info: app_info, constraints:constraints, severity:SECURITY_WARNING);