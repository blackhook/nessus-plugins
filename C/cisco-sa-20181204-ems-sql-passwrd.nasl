#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152699);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/23");

  script_cve_id("CVE-2018-0468");
  script_xref(name:"TRA", value:"TRA-2017-02");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm09173");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20181204-ems-sql-passwrd");

  script_name(english:"Cisco Energy Management Suite Default PostgreSQL Password Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The Cisco Energy Management Suite installed on the remote host has a default password.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Energy Management Suite installed on the remote host is prior to 5.2.3. It, therefore, potentially
has a default password for the postgres account for the bundled PostgresSQL database. An unauthenticated, local attacker
can exploit this to gain privileged or administrator access to the database.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181204-ems-sql-passwrd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d1762bc");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm09173");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2018-42");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Energy Management Suite version 5.2.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0468");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:energy_management_suite");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_energy_management_web_detect.nbin");
  script_require_keys("installed_sw/Cisco Energy Management");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:'Cisco Energy Management', port:port, webapp:TRUE);

var constraints = [
  { 'min_version' : '4.4', 'fixed_version' : '5.2.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
