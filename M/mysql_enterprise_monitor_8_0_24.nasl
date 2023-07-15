##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148986);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2020-17527",
    "CVE-2020-17530",
    "CVE-2021-3450",
    "CVE-2021-23841",
    "CVE-2021-25122"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle MySQL Enterprise Monitor Multiple Vulnerabilities (Apr 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"MySQL Enterprise Monitor installed on the remote host is 8.0.x prior to 8.0.24. Therefore, it's affected by 
multiple vulnerabilities as referenced in the April 2021 CPU advisory.

  - Vulnerability in the MySQL Enterprise Monitor product of Oracle MySQL (component: Monitoring: General 
    (Apache Tomcat)). Supported versions that are affected are 8.0.23 and prior. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via multiple protocols to compromise MySQL Enterprise Monitor.
    Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to
    all MySQL Enterprise Monitor accessible data (CVE-2020-17527).

  - Vulnerability in the MySQL Enterprise Monitor product of Oracle MySQL (component: Monitoring: General 
    (Apache Struts)). Supported versions that are affected are 8.0.23 and prior. Easily exploitable vulnerability 
    allows unauthenticated attacker with network access via HTTPS to compromise MySQL Enterprise Monitor. Successful
    attacks of this vulnerability can result in takeover of MySQL Enterprise Monitor (CVE-2020-17530).

  - Vulnerability in the MySQL Enterprise Monitor product of Oracle MySQL (component: Monitoring: General (OpenSSL)).
    Supported versions that are affected are 8.0.23 and prior. Difficult to exploit vulnerability allows 
    unauthenticated attacker with network access via HTTPS to compromise MySQL Enterprise Monitor. Successful attacks
    of this vulnerability can result in unauthorized creation, deletion or modification access to critical data or 
    all MySQL Enterprise Monitor accessible data as well as unauthorized access to critical data or complete access 
    to all MySQL Enterprise Monitor accessible data (CVE-2021-3450).

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuapr2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2021.html");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujul2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2021 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17530");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts 2 Forced Multi OGNL Evaluation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_enterprise_monitor");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_enterprise_monitor_web_detect.nasl", "oracle_mysql_enterprise_monitor_local_nix_detect.nbin", "oracle_mysql_enterprise_monitor_local_detect.nbin");
  script_require_keys("installed_sw/MySQL Enterprise Monitor");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'MySQL Enterprise Monitor');
var constraints = [{ 'min_version' : '8.0', 'fixed_version' : '8.0.24' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
