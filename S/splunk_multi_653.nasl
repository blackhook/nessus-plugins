#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(121043);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/24");

  script_cve_id(
    "CVE-2018-7427",
    "CVE-2018-7429",
    "CVE-2018-7431",
    "CVE-2018-7432"
  );
  script_bugtraq_id(105730);

  script_name(english:"Splunk Enterprise 6.0.x < 6.0.14 / 6.1.x < 6.1.13 / 6.2.x < 6.2.14 / 6.3.x < 6.3.11 / 6.4.x < 6.4.8 / 6.5.x < 6.5.3 or Splunk Light < 6.6.0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Splunk
running on the remote web server is Splunk Light prior to 6.6.0
or Splunk Enterprise 6.0.x prior to 6.0.14, 6.1.x prior to 6.1.13,
6.2.x prior to 6.2.14, 6.3.x prior to 6.3.11, 6.4.x prior to 6.4.8, or
6.5.x prior to 6.5.3. It is, therefore,affected by multiple
vulnerabilities:

  - A cross-site scripting (XSS) vulnerability exists due to improper
    validation of user-supplied input before returning it to users. 
    An unauthenticated, remote attacker can exploit this, by 
    convincing a user to click a specially crafted URL, to execute 
    arbitrary script code in a user's browser session. (CVE-2018-7427)

  - A denial of service (DoS) vulnerability exists in the Splunk
    daemon due to improper validation of HTTP requests. An
    unauthenticated, remote attacker can exploit this, via a specially
    crafted HTTP request, to cause the application to stop responding.
    (CVE-2018-7432)

  - A directory traversal vulnerability exists in Splunk Django App
    due to improper validation of user-supplied input by the affected
    software. An authenticated, remote attacker can exploit this, by
    sending a URI that contains directory traversal characters, to
    disclose the contents of files located outside of the server's 
    restricted path. (CVE-2018-7431)

  - A denial of service (DoS) vulnerability exists in the Splunk
    daemon due to improper handling of malformed HTTP requests. An
    unauthenticated, remote attacker can exploit this, via a specially
    crafted HTTP request, to cause the application to stop responding.
    (CVE-2018-7429)");
  script_set_attribute(attribute:"see_also", value:"https://www.splunk.com/view/SP-CAAAP5T#announce1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Splunk Enterprise version 6.0.14 / 6.1.13 / 6.2.14 /
6.3.11 / 6.4.8 / 6.5.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7427");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-7431");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("splunkd_detect.nasl", "splunk_web_detect.nasl");
  script_require_keys("installed_sw/Splunk");
  script_require_ports("Services/www", 8089, 8000);

  exit(0);
}

include("vcf.inc");
include("http.inc");

app = "Splunk";
port = get_http_port(default:8000, embedded:TRUE);

app_info = vcf::get_app_info(app:app, port: port);
if (app_info['License'] == "Enterprise")
{
  constraints = [
    { "min_version" : "6.5.0", "fixed_version" : "6.5.3" },
    { "min_version" : "6.4.0", "fixed_version" : "6.4.8" },
    { "min_version" : "6.3.0", "fixed_version" : "6.3.11" },
    { "min_version" : "6.2.0", "fixed_version" : "6.2.14" },
    { "min_version" : "6.1.0", "fixed_version" : "6.1.13" },
    { "min_version" : "6.0.0", "fixed_version" : "6.0.14" }
  ];
}
else if (app_info['License'] == "Light")
  constraints = [{ "fixed_version" : "6.6.0" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});
