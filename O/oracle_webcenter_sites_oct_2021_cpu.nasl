#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154418);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-12415",
    "CVE-2019-13990",
    "CVE-2020-5258",
    "CVE-2021-26272",
    "CVE-2021-27906",
    "CVE-2021-29505"
  );
  script_xref(name:"IAVA", value:"2021-A-0480");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle WebCenter Sites Multiple Vulnerabilities (Oct 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Oracle WebCenter Sites component of Oracle Fusion Middleware is affected by multiple vulnerabilities.

  - Component: WebCenter Sites (Terracotta Quartz Scheduler)). The supported
  versions that are affected are 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable
  vulnerability allows unauthenticated attacker with network access via HTTP to
  compromise Oracle WebCenter Sites. Successful attacks of this vulnerability
  can result in takeover of Oracle WebCenter Sites. (CVE-2019-13990)

  - Component: WebCenter Sites (XStream)). The supported versions that are
  affected are 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability
  allows low privileged attacker with network access via HTTP to compromise
  Oracle WebCenter Sites. Successful attacks of this vulnerability can result
  in takeover of Oracle WebCenter Sites. (CVE-2021-29505)

  - Component: WebCenter Sites (dojo)). The supported versions that are
  affected are 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability
  allows unauthenticated attacker with network access via HTTP to compromise
  Oracle WebCenter Sites. Successful attacks of this vulnerability can result
  in unauthorized creation, deletion or modification access to critical data or
  all Oracle WebCenter Sites accessible data. (CVE-2020-5258)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2021.html");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuoct2021cvrf.xml");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2021 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-13990");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:webcenter_sites");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_webcenter_sites_installed.nbin", "oracle_enum_products_win.nbin");
  script_require_keys("SMB/WebCenter_Sites/Installed");

  exit(0);
}
include('vcf_extras_oracle_webcenter_sites.inc');

var app_info = vcf::oracle_webcenter_sites::get_app_info();

# neither patch updates revision number
var constraints = [
  {'min_version' : '12.2.1.3', 'fixed_version' : '12.2.1.3.211019'},
  {'min_version' : '12.2.1.4', 'fixed_version' : '12.2.1.4.211019'}
];

vcf::oracle_webcenter_sites::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);

