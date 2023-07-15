#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157377);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2021-25296", "CVE-2021-25297", "CVE-2021-25298");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/02/01");

  script_name(english:"Nagios XI 5.7.5 Command Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web application that may be affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to the self-reported version of Nagios XI, the remote host may be affected by multiple vulnerabilities, including
the following:

 - A command injection vulnerability in the file /usr/local/nagiosxi/html/includes/configwizards/windowswmi/windowswmi.inc.php
   due to improper sanitization of authenticated user-controlled input by a single HTTP request (CVE-2021-25296).

 - A command injection vulnerability in the file /usr/local/nagiosxi/html/includes/configwizards/switch/switch.inc.php
   due to improper sanitization of authenticated user-controlled input by a single HTTP request (CVE-2021-25297).

 - A command injection vulnerability in the file /usr/local/nagiosxi/html/includes/configwizards/cloud-vm/cloud-vm.inc.php
   due to improper sanitization of authenticated user-controlled input by a single HTTP request (CVE-2021-25298).

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.nagios.com/downloads/nagios-xi/change-log/");
  script_set_attribute(attribute:"see_also", value:"https://www.nagios.com/products/security/");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25298");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Nagios XI 5.5.6 to 5.7.5 - ConfigWizards Authenticated Remote Code Exection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nagios:nagios_xi");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2023 Tenable Network Security, Inc.");

  script_dependencies("nagios_enterprise_detect.nasl");
  script_require_keys("installed_sw/nagios_xi", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http_func.inc');
include('vcf_extras.inc');

var port = get_http_port(default:80, embedded:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app_info = vcf::nagiosxi::get_app_info(port:port);

var constraints = [
    {'min_version': '5.7.5', 'max_version': '5.7.5.99999', 'fixed_display': 'See vendor advisory'}
];

# DOn't use the vcf::nagiosxi as we don't want R201* versions to be flagged
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
