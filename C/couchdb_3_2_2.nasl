#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(161177);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/04");

  script_cve_id("CVE-2022-24706");
  script_xref(name:"IAVB", value:"2022-B-0012-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/09/15");

  script_name(english:"Apache CouchDB < 3.2.2 Remote Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is potentially affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of CouchDB running on the remote host is prior to 3.2.2 It is, therefore,
potentially affected by a remote privilege escalation vulnerability. An attacker can access an improperly secured
default installation without authenticating and gain admin privileges.

Note that Nessus did not actually test for these flaws but instead, has relied on the version in CouchDB's banner.");
  script_set_attribute(attribute:"see_also", value:"https://docs.couchdb.org/en/3.2.2/cve/2022-24706.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to CouchDB 3.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24706");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Couchdb Erlang RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:couchdb");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("couchdb_detect.nasl");
  script_require_keys("www/couchdb", "Settings/ParanoidReport");
  script_require_ports("Services/www", 5984, 6984);

  exit(0);
}

include('http.inc');
include('vcf.inc');

var port = get_http_port(default:5984);
var app = vcf::get_app_info(app:'couchdb', webapp:TRUE, port:port);

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

constraints = [
  {'fixed_version' : '3.2.2'}
];

vcf::check_version_and_report(
  app_info:app,
  constraints:constraints,
  severity:SECURITY_HOLE
);
