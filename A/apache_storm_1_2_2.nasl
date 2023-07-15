#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122487);
  script_version("1.3");
  script_cvs_date("Date: 2019/10/31 15:18:51");

  script_cve_id("CVE-2018-8008");
  script_bugtraq_id(104418);

  script_name(english:"Apache Storm < 1.1.3 / 1.2.x < 1.2.2 arbitrary file write vulnerability");
  script_summary(english:"Checks for the product and version in the about page.");

  script_set_attribute(attribute:"synopsis", value:
"A distributed computation application running on the remote host is affected by
an arbitrary file write vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Storm running on the remote host is prior to 
1.1.3 or 1.2.x prior to 1.2.2. It is, therefore, affected by an 
arbitrary file write vulnerability.");
  # https://lists.apache.org/thread.html/613b2fca8bcd0a3b12c0b763ea8f7cf62e422e9f79fce6cfa5b08a58@%3Cdev.storm.apache.org%3E
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?533249db");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Storm version 1.1.3 / 1.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8008");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_storm_detect.nbin", "apache_storm_webui_detect.nbin");
  script_require_ports("installed_sw/Apache Storm", "installed_sw/Apache Storm WebUI", "Services/apache_storm", 8080, 6627);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("vcf.inc");
include("vcf_extras.inc");

vcf::apache_storm::initialize();

if(!isnull(get_kb_item("installed_sw/Apache Storm")))
{
  port = get_service(svc:"apache_storm", exit_on_fail:TRUE);
  app = vcf::get_app_info(app:"Apache Storm", port:port);
}
else if(!isnull(get_kb_item("installed_sw/Apache Storm WebUI")))
{
  # Since the web app is just a web app and version could be misreported.
  if (report_paranoia < 2)
    audit(AUDIT_PARANOID);
  port = get_http_port(default:8080);
  app = vcf::get_app_info(app:"Apache Storm WebUI", webapp:TRUE, port:port);
}
else audit(AUDIT_NOT_INST, "Apache Storm");

constraints = 
[
  {"max_version" : "1.0.6", "fixed_version" : "1.1.3"},
  {"min_version" : "1.1.0", "fixed_version" : "1.1.3"},
  {"min_version" : "1.2.0", "fixed_version" : "1.2.2"}
];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_WARNING, strict:FALSE);
