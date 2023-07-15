##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146498);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/19");

  script_cve_id("CVE-2019-15641");

  script_name(english:"Webmin <= 1.930 XXE");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an XXE vulnerability.");
  script_set_attribute(attribute:"description", value:
"An XML external entity (XXE_ vulnerability exists in Webmin through 1.930 in xmlrpc.cgi due to an incorrectly
configured XML parser accepting XML external entities from an untrusted source. A remote, authenticated attacker can
exploit this,via specially crafted XML data, to disclose sensitive information.
 
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://www.webmin.com/changes.html");
  script_set_attribute(attribute:"see_also", value:"https://www.calypt.com/blog/index.php/authenticated-xxe-on-webmin/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Webmin 1.940 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15641");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:webmin:webmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

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
  { 'max_version':'1.930', 'fixed_version':'1.940' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
