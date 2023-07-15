#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(99664);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2015-7559");
  script_bugtraq_id(97967);

  script_name(english:"Apache ActiveMQ 5.x < 5.14.5 ControlCommand DoS");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by a denial
of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache ActiveMQ running on the remote host is 5.x prior
to 5.14.5. It is, therefore, affected by an unspecified flaw in
ControlCommand handling by the ActiveMQConnection::onControlCommand()
function within file ActiveMQConnection.java. An unauthenticated,
remote attacker can exploit this to cause a denial of service
condition.");
  script_set_attribute(attribute:"see_also", value:"http://activemq.apache.org/activemq-5145-release.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache ActiveMQ version 5.14.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7559");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:activemq");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("activemq_web_console_detect.nasl");
  script_require_keys("installed_sw/ActiveMQ");
  script_require_ports("Services/www", 8161);

  exit(0);
}

include("http.inc");
include("vcf.inc");

app = 'ActiveMQ';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8161);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

constraints = [
  { "min_version" : "5.0.0", "max_version" : "5.14.4", "fixed_version" : "5.14.5" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
