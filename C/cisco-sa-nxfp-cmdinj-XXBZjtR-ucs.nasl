#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171894);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/14");

  script_cve_id("CVE-2023-20015");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc52151");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd11206");
  script_xref(name:"IAVA", value:"2023-A-0114");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxfp-cmdinj-XXBZjtR");

  script_name(english:"Cisco UCS Fabric Interconnects Command Injection (cisco-sa-nxfp-cmdinj-XXBZjtR)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unified Computing System (UCS) Fabric Interconnect is affected by a
command injection vulnerability. Due to insufficient input validation of commands supplied by the user, an
authenticated attacker can execute unauthorized commands within the CLI. On Cisco UCS 6400 and UCS 6500 Series Fabric
Interconnects, an attacker with Administrator privileges could execute commands on the underlying operating system with
root-level privileges.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxfp-cmdinj-XXBZjtR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?169879f8");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75057
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?824d6bb6");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc52151");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd11206");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwc52151 and CSCwd11206");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20015");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_computing_system");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucs_manager_version.nasl");
  script_require_keys("installed_sw/cisco_ucs_manager");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('ccf.inc');
include('http.inc');

# UCS Manager only runs on Series 6200/6300/6400/6500 Fabric interconnects
# so we don't need to check a model
var app = 'cisco_ucs_manager';
get_install_count(app_name:app, exit_if_zero:TRUE);

var port = get_http_port(default:80);
var install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);

var url = build_url(qs:install['path'], port:port);
var version = tolower(install['version']);

if (cisco_gen_ver_compare(a:version, b:'4.0(4o)') < 0 ||
    (cisco_gen_ver_compare(a:version, b:'4.1' && cisco_gen_ver_compare(a:version, b:'4.1(3k)')) ||
    (cisco_gen_ver_compare(a:version, b:'4.2' && cisco_gen_ver_compare(a:version, b:'4.2(2d)'))))
  )
{
  var report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : See vendor advisory.' +
    '\n  Cisco bug ID      : CSCwc52151, CSCwd11206'
    '\n';
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}

audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Cisco UCS Manager', url, version);


