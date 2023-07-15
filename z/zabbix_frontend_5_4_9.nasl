#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158452);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2022-23131",
    "CVE-2022-23132",
    "CVE-2022-23133",
    "CVE-2022-23134"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/08");

  script_name(english:"Zabbix 5.4.x < 5.4.9 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Zabbix running on the remote host is 5.4.x prior to
5.4.9. It is, therefore, affected by multiple vulnerabilities:

  - In the case of instances where the SAML SSO authentication is enabled (non-default), session data can be modified
    by a malicious actor, because a user login stored in the session was not verified. Malicious unauthenticated actor
    may exploit this issue to escalate privileges and gain admin access to Zabbix Frontend. To perform the attack,
    SAML authentication is required to be enabled and the actor has to know the username of Zabbix user (or use the
    guest account, which is disabled by default). (CVE-2022-23131)

  - During Zabbix installation from RPM, DAC_OVERRIDE SELinux capability is in use to access PID files in
    [/var/run/zabbix] folder. In this case, Zabbix Proxy or Server processes can bypass file read, write and execute
    permissions check on the file system level. (CVE-2022-23132)

  - An authenticated user can create a hosts group from the configuration with XSS payload, which will be available
    for other users. (CVE-2022-23133)

  - After the initial setup process, some steps of setup.php file are reachable not only by super-administrators, but
    by unauthenticated users as well. Malicious actor can pass step checks and potentially change the configuration of
    Zabbix Frontend. (CVE-2022-23134)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.zabbix.com/browse/ZBX-20350");
  script_set_attribute(attribute:"see_also", value:"https://support.zabbix.com/browse/ZBX-20341");
  script_set_attribute(attribute:"see_also", value:"https://support.zabbix.com/browse/ZBX-20388");
  script_set_attribute(attribute:"see_also", value:"https://support.zabbix.com/browse/ZBX-20384");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zabbix version 5.8.9 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23132");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-23131");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zabbix:zabbix");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("zabbix_frontend_detect.nasl");
  script_require_keys("installed_sw/zabbix");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app = 'zabbix';
get_install_count(app_name:app, exit_if_zero:TRUE);

var port = get_http_port(default:80);

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  {'min_version':'5.4.0', 'fixed_version':'5.4.9'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
