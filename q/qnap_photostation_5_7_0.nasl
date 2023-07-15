#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117905);
  script_version("1.3");
  script_cvs_date("Date: 2019/04/05 23:25:05");

  script_cve_id("CVE-2018-0715");

  script_name(english:"QNAP Photo Station < 5.7.0 Cross-Site Scripting Vulnerability");
  script_summary(english:"Checks for the product and version in the api.");

  script_set_attribute(attribute:"synopsis", value:
"A photo gallery application running on the remote NAS is affected by
a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Photo Station running on the remote QNAP NAS is
prior to 5.7.0. It is, therefore, affected by a cross-site
scripting vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://www.qnap.com/en-us/security-advisory/nas-201808-23");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Photo Station 5.7.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0715");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:qnap:photo_station");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("qnap_photostation_detect.nbin");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("vcf.inc");

port = get_http_port(default:8080);
app = vcf::get_app_info(app:"QNAP Photo Station", webapp:TRUE, port:port);
flags = make_array("xss", TRUE);

constraints = [{"fixed_version" : "5.7.0"}];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_WARNING, strict:FALSE, flags:flags);
