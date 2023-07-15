#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132583);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2019-17558");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Apache Solr < 8.4.0 Remote Code Execution");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java application that is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Solr running on the remote host is at least 5.0.0 and prior to 8.4.0. It is, therefore, affected
by a remote code execution vulnerability. A remote code execution vulnerability exists in VelocityResponseWriter due to
a flaw in the velocity template parameter. An unauthenticated, remote attacker can exploit this to bypass authentication
and execute arbitrary commands with the privileges of Apache Solr.");
  script_set_attribute(attribute:"see_also", value:"http://lucene.apache.org/solr/news.html");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/jira/browse/SOLR-13971");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/jira/browse/SOLR-14025");
  script_set_attribute(attribute:"see_also", value:"https://vuldb.com/?id.147906");
  # https://www.tenable.com/blog/apache-solr-vulnerable-to-remote-code-execution-zero-day-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b63da8fd");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Solr version 8.4.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17558");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Solr Remote Code Execution via Velocity Template');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:solr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("solr_detect.nbin");
  script_require_keys("installed_sw/Apache Solr");
  script_require_ports("Services/www", 8983);

  exit(0);
}

include('vcf.inc');
include('http.inc');

app = 'Apache Solr';
get_install_count(app_name:app,exit_if_zero:TRUE);
port    = get_http_port(default:8983);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  {'min_version' : '5.0.0',  'fixed_version' : '7.7.3' },
  {'min_version' : '8.0.0',  'fixed_version' : '8.4.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
