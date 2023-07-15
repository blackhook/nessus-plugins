#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(148925);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-12402", "CVE-2020-9489", "CVE-2020-11612");
  script_xref(name:"IAVA", value:"2021-A-0326");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle WebCenter Portal Multiple Vulnerabilities (Apr 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application server installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle WebCenter Portal installed on the remote host is missing a security patch from the January 2021
Critical Patch Update (CPU). It is, therefore, affected by the following vulnerabilities:

  - Vulnerability in the Oracle WebCenter Portal product of Oracle Fusion Middleware (component: Security Framework 
  (Apache Commons Compress)). Supported versions that are affected are 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable
  vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebCenter Portal. 
  Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently 
  repeatable crash (complete DOS) of Oracle WebCenter Portal (CVE-2019-12402).

  - Vulnerability in the Oracle WebCenter Portal product of Oracle Fusion Middleware (component: Security Framework 
  (Netty)). Supported versions that are affected are 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows
  unauthenticated attacker with network access via HTTP to compromise Oracle WebCenter Portal. Successful attacks of 
  this vulnerability can result in takeover of Oracle WebCenter Portal (CVE-2020-11612). 

  - Vulnerability in the Oracle WebCenter Portal product of Oracle Fusion Middleware (component: Security Framework 
  (Apache Tika)). Supported versions that are affected are 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability
   allows unauthenticated attacker with logon to the infrastructure where Oracle WebCenter Portal executes to 
   compromise Oracle WebCenter Portal. Successful attacks require human interaction from a person other than the 
   attacker. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
  repeatable crash (complete DOS) of Oracle WebCenter Portal (CVE-2020-9489).

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuapr2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2021 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11612");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:webcenter_portal");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_webcenter_portal_installed.nbin");
  script_require_keys("installed_sw/Oracle WebCenter Portal");

  exit(0);
}

include('vcf_extras_oracle_webcenter_portal.inc');

var app_info = vcf::oracle_webcenter_portal::get_app_info();

var constraints = [
  {'min_version' : '11.1.1.9', 'fixed_version' : '11.1.1.9.210115'},
  {'min_version' : '12.2.1.3', 'fixed_version' : '12.2.1.3.210225'},
  {'min_version' : '12.2.1.4', 'fixed_version' : '12.2.1.4.210225'}
];

vcf::oracle_webcenter_portal::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);

