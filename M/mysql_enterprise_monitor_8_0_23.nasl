##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145538);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-10086", "CVE-2020-5408", "CVE-2020-5421");
  script_xref(name:"IAVA", value:"2021-A-0038");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle MySQL Enterprise Monitor Multiple Vulnerabilities (Jan 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"MySQL Enterprise Monitor installed on the remote host is 8.0.x prior to 8.0.23. Therefore, it's affected by 
multiple vulnerabilities as referenced in the January 2021 CPU advisory.

  - Vulnerability in the MySQL Enterprise Monitor product of Oracle MySQL (component: Service Manager (Apache
    Commons BeanUtils)). Supported versions that are affected are 8.0.22 and prior. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via HTTPS to compromise MySQL Enterprise
    Monitor. Successful attacks of this vulnerability can result in unauthorized update, insert or delete
    access to some of MySQL Enterprise Monitor accessible data as well as unauthorized read access to a subset
    of MySQL Enterprise Monitor accessible data and unauthorized ability to cause a partial denial of service
    (partial DOS) of MySQL Enterprise Monitor. (CVE-2019-10086)

  - Vulnerability in the MySQL Enterprise Monitor product of Oracle MySQL (component: Service Manager (Spring
    Framework)). Supported versions that are affected are 8.0.22 and prior. Difficult to exploit vulnerability
    allows low privileged attacker with network access via HTTPS to compromise MySQL Enterprise Monitor.
    Successful attacks require human interaction from a person other than the attacker and while the
    vulnerability is in MySQL Enterprise Monitor, attacks may significantly impact additional products.
    Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification
    access to critical data or all MySQL Enterprise Monitor accessible data as well as unauthorized read
    access to a subset of MySQL Enterprise Monitor accessible data. (CVE-2020-5421)

  - Vulnerability in the MySQL Enterprise Monitor product of Oracle MySQL (component: Service Manager (Spring
    Security)). Supported versions that are affected are 8.0.22 and prior. Easily exploitable vulnerability
    allows low privileged attacker with network access via HTTPS to compromise MySQL Enterprise Monitor.
    Successful attacks of this vulnerability can result in unauthorized access to critical data or complete
    access to all MySQL Enterprise Monitor accessible data. (CVE-2020-5408)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujan2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2021 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10086");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_enterprise_monitor");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_enterprise_monitor_web_detect.nasl");
  script_require_keys("installed_sw/MySQL Enterprise Monitor");
  script_require_ports("Services/www", 18443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

port = get_http_port(default:18443);
app_info = vcf::get_app_info(app:'MySQL Enterprise Monitor', port:port, webapp:true);

constraints = [
  { 'min_version' : '8.0', 'fixed_version' : '8.0.23' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
