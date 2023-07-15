#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138896);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/27");

  script_cve_id("CVE-2019-10072");

  script_name(english:"MySQL Enterprise Monitor 8.x < 8.0.18 DoS (Oct 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"MySQL Enterprise Monitor running on the remote host is affected by a denial of service vulnerability");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in MySQL Enterprise Monitor due to an HTTP/2 connection window
exhaustion on write. Therefore, An unauthenticated, remote attacker can exploit this issue, by not sending WINDOW_UPDATE
messages, to cause the system to stop responding.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2019.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL Enterprise Monitor version 8.0.18 or later as referenced in the Oracle security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10072");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_enterprise_monitor");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_enterprise_monitor_web_detect.nasl");
  script_require_keys("installed_sw/MySQL Enterprise Monitor");
  script_require_ports("Services/www", 18443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

app  = 'MySQL Enterprise Monitor';
port = get_http_port(default:18443);

app_info = vcf::get_app_info(app:app, port:port, webapp:true);

constraints = [
  { 'min_version' : '8.0', 'fixed_version' : '8.0.18' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
