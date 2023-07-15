##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(166377);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/30");

  script_cve_id(
    "CVE-2021-23450",
    "CVE-2021-43859",
    "CVE-2022-24729",
    "CVE-2022-32532"
  );

  script_name(english:"Oracle WebCenter Sites (Oct 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 12.2.1.3.0 and 12.2.1.4.0 versions of WebCenter Sites installed on the remote host are affected by multiple
vulnerabilities as referenced in the October 2022 CPU advisory.

  - Vulnerability in the Oracle WebCenter Sites product of Oracle Fusion Middleware (component: Centralized Thirdparty 
    Jars (dojo)). Supported versions that are affected are 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability 
    allows unauthenticated attacker with network access via HTTP to compromise Oracle WebCenter Sites. Successful 
    attacks of this vulnerability can result in takeover of Oracle WebCenter Sites. (CVE-2021-23450)

  - Vulnerability in the Oracle WebCenter Sites product of Oracle Fusion Middleware (component: WebCenter Sites 
    (XStream)). Supported versions that are affected are 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability 
    allows unauthenticated attacker with network access via HTTP to compromise Oracle WebCenter Sites. Successful 
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash 
    (complete DOS) of Oracle WebCenter Sites. (CVE-2021-43859)

  - Vulnerability in the Oracle WebCenter Sites product of Oracle Fusion Middleware (component: WebCenter Sites 
    (CKEditor)). Supported versions that are affected are 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability 
    allows unauthenticated attacker with network access via HTTP to compromise Oracle WebCenter Sites. Successful 
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash 
    (complete DOS) of Oracle WebCenter Sites. (CVE-2022-24729)

  - CVE-2022-32532	Vulnerability in the Oracle WebCenter Sites product of Oracle Fusion Middleware (component: 
    WebCenter Sites (Apache Shiro)). Supported versions that are affected are 12.2.1.3.0 and 12.2.1.4.0. Easily 
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle 
    WebCenter Sites. Successful attacks of this vulnerability can result in takeover of Oracle WebCenter Sites. 
    (CVE-2022-32532)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuoct2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2022 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32532");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:webcenter_sites");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_webcenter_sites_installed.nbin", "oracle_enum_products_win.nbin");
  script_require_keys("SMB/WebCenter_Sites/Installed");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_oracle_webcenter_sites.inc');

var app_info = vcf::oracle_webcenter_sites::get_app_info();

var constraints = [
  { 'min_version' : '12.2.1.3.0', 'fixed_version' : '12.2.1.3.221017' },
  { 'min_version' : '12.2.1.4.0', 'fixed_version' : '12.2.1.4.221017' }
];

vcf::oracle_webcenter_sites::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
