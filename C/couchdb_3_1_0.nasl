#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136945);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/17");

  script_cve_id("CVE-2020-1955");
  script_xref(name:"IAVB", value:"2020-B-0029-S");

  script_name(english:"Apache CouchDB 3.x < 3.0.1 Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is potentially affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of CouchDB running on the remote host is 3.x prior to 3.0.1. It is, therefore, 
  potentially affected by a privilege escalation which could allow users to access endpoints which should require 
  authentication.

  Note that Nessus did not actually test for these flaws but instead, has relied on the version in CouchDB's banner.");
  script_set_attribute(attribute:"see_also", value:"https://docs.couchdb.org/en/master/cve/2020-1955.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to CouchDB 3.0.1, 3.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1955");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:couchdb");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("couchdb_detect.nasl");
  script_require_keys("www/couchdb", "Settings/ParanoidReport");
  script_require_ports("Services/www", 5984, 6984);

  exit(0);
}

include('http.inc');
include('vcf.inc');

port = get_http_port(default:5984);
app = vcf::get_app_info(app:'couchdb', webapp:TRUE, port:port);

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

constraints = [
  {'min_version' : '3.0', 'fixed_version' : '3.0.1', 'fixed_display': '3.0.1 / 3.1.0'}
];

vcf::check_version_and_report(
  app_info:app,
  constraints:constraints,
  severity:SECURITY_WARNING
);
