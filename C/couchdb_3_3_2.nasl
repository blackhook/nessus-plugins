#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175115);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/14");

  script_cve_id("CVE-2023-26268");
  script_xref(name:"IAVB", value:"2023-B-0030");

  script_name(english:"Apache CouchDB < 3.2.3 / 3.3.x < 3.3.2 Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of CouchDB running on the remote host is prior to 3.2.3 or 3.3.x prior to 3.3,2.
It is, therefore, affected by an information disclosure vulnerability. Design documents with matching document IDs,
from databases on the same cluster, may share a mutable Javascript environment when using specific design document
functions.

Note that Nessus did not actually test for these flaws but instead, has relied on the version in CouchDB's banner.");
  script_set_attribute(attribute:"see_also", value:"https://docs.couchdb.org/en/latest/cve/2023-26268.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to CouchDB 3.2.3, 3.3.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-26268");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:couchdb");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("couchdb_detect.nasl");
  script_require_keys("www/couchdb");
  script_require_ports("Services/www", 5984, 6984);

  exit(0);
}

include('http.inc');
include('vcf.inc');

var port = get_http_port(default:5984);
var app = vcf::get_app_info(app:'couchdb', webapp:TRUE, port:port);

var constraints = [
  {'fixed_version' : '3.2.3'},
  {'min_version': '3.3.0', 'fixed_version': '3.3.2'}
];

vcf::check_version_and_report(
  app_info:app,
  constraints:constraints,
  severity:SECURITY_WARNING
);
