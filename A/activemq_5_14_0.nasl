#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117601);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2016-3088");
  script_bugtraq_id(90827);
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/08/10");

  script_name(english:"Apache ActiveMQ 5.x < 5.14.0 ActiveMQ Fileserver web application remote code execution (Xbash)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache ActiveMQ running on the remote host is 5.x prior
to 5.14.0. It is, therefore, affected by a remote code execution 
vulnerability. The Fileserver web application allows remote attackers
to upload and execute arbitrary files.");
  # http://activemq.apache.org/security-advisories.data/CVE-2016-3088-announcement.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2581a08b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache ActiveMQ version 5.14.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3088");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ActiveMQ web shell upload');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:activemq");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("activemq_web_console_detect.nasl");
  script_require_keys("installed_sw/ActiveMQ", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8161);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");
include("vcf.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = 'ActiveMQ';
port = get_http_port(default:8161);
app = vcf::get_app_info(app:app_name, port:port, webapp:TRUE);

constraints = [{"min_version" : "5.0", "fixed_version" : "5.14.0"}];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_HOLE, strict:FALSE);
