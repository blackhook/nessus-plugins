##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146531);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/19");

  script_cve_id("CVE-2020-8820", "CVE-2020-8821", "CVE-2020-12670");

  script_name(english:"Webmin <= 1.941 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version  of Webmin on the remote host is affected by multiple
vulnerabilities, including the  following:

  - An XSS Vulnerability exists in Webmin 1.941 and earlier affecting the Cluster Shell Commands Endpoint.
    A user may enter any XSS Payload into the Command field and execute it. Then, after revisiting the Cluster
    Shell Commands Menu, the XSS Payload will be rendered and executed. (CVE-2020-8820)

  - An Improper Data Validation Vulnerability exists in Webmin 1.941 and earlier affecting the Command Shell
    Endpoint. A user may enter HTML code into the Command field and submit it. Then, after visiting the Action
    Logs Menu and displaying logs, the HTML code will be rendered (however, JavaScript is not executed).
    Changes are kept across users. (CVE-2020-8821)

  - XSS exists in Webmin 1.941 and earlier affecting the Save function of the Read User Email Module /
    mailboxes Endpoint when attempting to save HTML emails. This module parses any output without sanitizing
    SCRIPT elements, as opposed to the View function, which sanitizes the input correctly. A malicious user
    can send any JavaScript payload into the message body and execute it if the user decides to save that
    email. (CVE-2020-12670)

 Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
 number.");
  script_set_attribute(attribute:"see_also", value:"http://www.webmin.com/changes.html");
  script_set_attribute(attribute:"see_also", value:"http://www.webmin.com/security.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Webmin 1.953 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12670");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:webmin:webmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("webmin.nasl");
  script_require_keys("www/webmin", "Settings/ParanoidReport");
  script_require_ports("Services/www", 10000);

  exit(0);
}

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = 'Webmin';
port = get_http_port(default:10000, embedded: TRUE);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'max_version':'1.941', 'fixed_display':'1.953' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);
