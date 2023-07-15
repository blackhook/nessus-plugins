#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170197);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/22");

  script_cve_id("CVE-2021-31812", "CVE-2022-40664");
  script_xref(name:"IAVA", value:"2023-A-0039");

  script_name(english:"Oracle WebCenter Sites (Jan 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 12.2.1.4.0 version of WebCenter Sites installed on the remote host is affected by multiple vulnerabilities as
referenced in the January 2023 CPU advisory.

  - Vulnerability in the Oracle WebCenter Sites product of Oracle Fusion Middleware (component: WebCenter
    Sites (Apache PDFBox)). The supported version that is affected is 12.2.1.4.0. Easily exploitable
    vulnerability allows unauthenticated attacker with logon to the infrastructure where Oracle WebCenter
    Sites executes to compromise Oracle WebCenter Sites. Successful attacks require human interaction from a
    person other than the attacker. Successful attacks of this vulnerability can result in unauthorized
    ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle WebCenter Sites.
    (CVE-2021-31812)

  - Vulnerability in the Oracle WebCenter Sites product of Oracle Fusion Middleware (component: WebCenter
    Sites (Apache Shiro)). The supported version that is affected is 12.2.1.4.0. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebCenter
    Sites. Successful attacks of this vulnerability can result in takeover of Oracle WebCenter Sites.
    (CVE-2022-40664)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2023 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31812");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/20");

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
  { 'min_version' : '12.2.1.4.0', 'fixed_version' : '12.2.1.4.230117' }
];

vcf::oracle_webcenter_sites::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
