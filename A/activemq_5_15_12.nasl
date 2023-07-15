#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(138597);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-1941");
  script_xref(name:"IAVB", value:"2020-B-0039-S");

  script_name(english:"Apache ActiveMQ 5.x < 5.15.12 XSS (CVE-2020-1941)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache ActiveMQ running on the remote host is 5.x prior to 5.15.12. It is, therefore, affected by a
cross-site scripting (XSS) vulnerability in the webconsole admin GUI. An unauthenticated, remote attacker can exploit
this issue, by convincing a user to click a specially crafted URL, to execute code in a user's browser session.");
  # http://activemq.apache.org/security-advisories.data/CVE-2020-1941-announcement.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1144f21d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache ActiveMQ version 5.15.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1941");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:activemq");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("activemq_web_console_detect.nasl");
  script_require_keys("installed_sw/ActiveMQ", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8161);

  exit(0);
}

include('http.inc');
include('vcf.inc');

app_name = 'ActiveMQ';
port = get_http_port(default:8161);
app = vcf::get_app_info(app:app_name, port:port, webapp:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

constraints = [{'min_version' : '5.0', 'fixed_version' : '5.15.12'}];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_WARNING, strict:FALSE, flags:{'xss':TRUE});
