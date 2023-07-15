#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110773);
  script_version("1.2");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2017-9506");

  script_name(english:"Atlassian Crucible < 4.3.2 OAuth Plugin IconUriServlet Internal Network Resource Disclosure CSRF");
  script_summary(english:"Checks the version of Crucible.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Atlassian Crucible installed on the remote host is
affected by an internal network resource disclosure (CSRF) 
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the installation of Atlassian
Crucible running on the remote host is prior to 4.3.2.
It is, therefore, affected by a internal network resource disclosure
(CSRF) vulnerability in the OAuth plugin IconUriServlet.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://ecosystem.atlassian.net/browse/OAUTH-344");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Crucible 4.3.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9506");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:crucible");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("crucible_detect.nasl");
  script_require_keys("installed_sw/crucible", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8060);

  exit(0);
}
include("http.inc");
include("vcf.inc");

port = get_http_port(default:8060);

app = "crucible";

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { "min_version" : "1.0.0", "fixed_version" : "4.3.2" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{"xsrf":TRUE});
