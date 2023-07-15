#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111967);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/29");

  script_cve_id("CVE-2018-11769");
  script_bugtraq_id(105046);
  script_xref(name:"IAVB", value:"2018-B-0099-S");

  script_name(english:"Apache CouchDB 1.x / 2.1.x <= 2.1.2 Privilege Escalation");
  script_summary(english:"Does a paranoid banner check on the web server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is potentially affected by a privilege 
escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of CouchDB running on the remote
host is 1.x or 2.1.x prior to 2.1.2. It is, therefore, potentially 
affected by a privilege escalation which could allow a CouchDB 
administrative user to gain remote code execution on the underlying
operating system. 

Note that Nessus did not actually test for these flaws but instead, has
relied on the version in CouchDB's banner.");
  script_set_attribute(attribute:"see_also", value:"http://docs.couchdb.org/en/stable/cve/2018-11769.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to CouchDB 2.2.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11769");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:couchdb");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("couchdb_detect.nasl");
  script_require_keys("Settings/ParanoidReport", "www/couchdb");
  script_require_ports("Services/www", 5984, 6984);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("vcf.inc");

port = get_http_port(default:5984);
app = vcf::get_app_info(app:"couchdb", webapp:TRUE, port:port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

constraints = [{"min_version" : "1.0", "max_version": "2.1.2", "fixed_version" : "2.2.0"}];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_HOLE, strict:FALSE);
