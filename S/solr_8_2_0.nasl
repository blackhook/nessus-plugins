#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131167);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/26");

  script_cve_id("CVE-2019-12409");

  script_name(english:"Apache Solr 8.1.1 / 8.2.0 Remote Code Execution Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java application that is affected by
a remote code vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Solr running on the remote web server is
affected by a remote code vulnerability as referenced in the advisory.");
  script_set_attribute(attribute:"see_also", value:"http://lucene.apache.org/solr/news.html");
  # https://lists.apache.org/thread.html/6640c7e370fce2b74e466a605a46244ccc40666ad9e3064a4e04a85d@%3Csolr-user.lucene.apache.org%3E
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?417249db");
  # https://issues.apache.org/jira/browse/SOLR-13647
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8d17b7dd");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Solr version 8.3.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12409");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:solr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("solr_detect.nbin", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Apache Solr", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8983);

  exit(0);
}

include("vcf.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

os = get_kb_item_or_exit("Host/OS");
confidence = get_kb_item_or_exit("Host/OS/Confidence");

if ("Windows" >< os && confidence > 80)
{
  audit(AUDIT_OS_NOT, "Linux-based");
}

app = "Apache Solr";
get_install_count(app_name:app,exit_if_zero:TRUE);
port    = get_http_port(default:8983);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  {"min_version" : "8.1.1",  "fixed_version" : "8.3.0" },
  {"min_version" : "8.2.0",  "fixed_version" : "8.3.0" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
