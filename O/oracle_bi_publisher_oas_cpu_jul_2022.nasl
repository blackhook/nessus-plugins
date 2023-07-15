##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164159);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/18");

  script_cve_id("CVE-2020-11023", "CVE-2022-22965");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/25");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Business Intelligence Publisher (OAS) (Jul 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 5.9.0.0.0 and All Supported Versions versions of Oracle Business Intelligence Enterprise Edition (OAS) installed
on the remote host are affected by multiple vulnerabilities as referenced in the July 2022 CPU advisory.

  - Vulnerability in the Oracle Business Intelligence Enterprise Edition product of Oracle Fusion Middleware
    (component: Service Administration UI (JQuery)). The supported version that is affected is 5.9.0.0.0.
    Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to
    compromise Oracle Business Intelligence Enterprise Edition. Successful attacks require human interaction
    from a person other than the attacker and while the vulnerability is in Oracle Business Intelligence
    Enterprise Edition, attacks may significantly impact additional products (scope change). Successful
    attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle
    Business Intelligence Enterprise Edition accessible data as well as unauthorized read access to a subset
    of Oracle Business Intelligence Enterprise Edition accessible data. (CVE-2020-11023)

  - Security-in-Depth issue in the Oracle BI Publisher product of Oracle Fusion Middleware (component: Web Service
    API (Spring Framework)). This vulnerability cannot be exploited in the context of this product.
    (CVE-2022-22965)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujul2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22965");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Spring Framework Class property RCE (Spring4Shell)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_intelligence_publisher");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_bi_publisher_installed.nbin");
  script_require_keys("installed_sw/Oracle Business Intelligence Publisher");

  exit(0);
}

include('vcf_extras.inc');

var app_info = vcf::get_app_info(app:'Oracle Business Intelligence Publisher');

var constraints = [
  # Oracle Analytics Server 5.9
  {'min_version': '12.2.5.9', 'fixed_version': '12.2.5.9.220714', 'patch': '34385848', 'bundle': '34385848'}
];

vcf::oracle_bi_publisher::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
