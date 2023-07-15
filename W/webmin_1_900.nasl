##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146497);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/19");

  script_cve_id("CVE-2018-19191");

  script_name(english:"Webmin 1.890 XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"A cross-site scripting (XSS) vulnerability exists in Webmin 1.890 due to improper validation of user-supplied input
before returning it to users. An unauthenticated, remote attacker can exploit this, by convincing a user to click a
specially crafted URL, to execute arbitrary script code in a user's browser session.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://www.webmin.com/changes.html");
  script_set_attribute(attribute:"see_also", value:"http://www.webmin.com/security.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Webmin 1.900 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19191");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/21");
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
  { 'equal':'1.890', 'fixed_display':'1.900' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE,
  flags:{xss:TRUE}
);
