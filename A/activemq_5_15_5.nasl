#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(112192);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/14");

  script_cve_id(
    "CVE-2012-0881",
    "CVE-2014-0114",
    "CVE-2015-5182",
    "CVE-2016-3092",
    "CVE-2016-5425",
    "CVE-2016-6325",
    "CVE-2016-8735",
    "CVE-2018-7489",
    "CVE-2018-8006"
  );
  script_bugtraq_id(
    67121,
    68753,
    91453,
    93472,
    93478,
    94463,
    103203,
    105156
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/02");

  script_name(english:"Apache ActiveMQ 5.x < 5.15.5 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by multiple
 vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache ActiveMQ running on the remote host is 5.x prior
to 5.15.5. It is, therefore, affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://activemq.apache.org/activemq-5155-release.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache ActiveMQ version 5.15.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7489");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts ClassLoader Manipulation Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:activemq");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { "min_version" : "5.0.0", "max_version" : "5.15.4", "fixed_version" : "5.15.5" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{xss:TRUE, xsrf:TRUE});
