#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117483);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-11775");
  script_bugtraq_id(105335);

  script_name(english:"Apache ActiveMQ Client 5.x < 5.15.6 TLS Hostname Verification Weakness");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by an
man-in-the-middle vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache ActiveMQ running on the remote host is 5.x
prior to 5.15.6. It is, therefore, affected by a flaw related to TLS
hostname verification and ActiveMQ Client that allows
man-in-the-middle attacks.");
  # https://activemq.apache.org/security-advisories.data/CVE-2018-11775-announcement.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2be62caa");
  script_set_attribute(attribute:"see_also", value:"https://activemq.apache.org/activemq-5156-release.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache ActiveMQ version 5.15.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11775");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:activemq");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("activemq_web_console_detect.nasl");
  script_require_keys("installed_sw/ActiveMQ", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8161);

  exit(0);
}


include("http.inc");
include("vcf.inc");

# Client has the problem
if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = 'ActiveMQ';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8161);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

constraints = [
  { "min_version" : "5", "fixed_version" : "5.15.6" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
