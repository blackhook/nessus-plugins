#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134568);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/16");

  script_cve_id("CVE-2020-3167");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp44264");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp44281");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr58699");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200226-fxos-ucs-cmdinj");
  script_xref(name:"IAVA", value:"2020-A-0085");

  script_name(english:"Cisco UCS Manager Software CLI Command Injection (cisco-sa-20200226-fxos-ucs-cmdinj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco UCS Manager Software is affected by a vulnerability in the CLI due to
insufficient input validation. An authenticated, local attacker can exploit this, by including crafted arguments to
specific commands, in order to execute arbitrary commands on the underlying OS with the privileges of the currently
logged-in user. On Cisco UCS 6400 Series Fabric Interconnects, the injected commands are executed with root privileges.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200226-fxos-ucs-cmdinj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5d34d6d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp44264");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp44281");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr58699");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvp44264, CSCvp44281, and CSCvr58699.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3167");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_computing_system");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucs_manager_version.nasl");
  script_require_keys("installed_sw/cisco_ucs_manager", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('http.inc');
include('install_func.inc');
include('cisco_func.inc');
include('audit.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

app = 'cisco_ucs_manager';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);
install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);

url = build_url(qs:install['path'], port:port);
version = tolower(install['version']);

if (
    ( cisco_gen_ver_compare(a:version, b:'0.0') >= 0 &&
      cisco_gen_ver_compare(a:version, b:'3.2(3n)') < 0
    ) ||
    ( cisco_gen_ver_compare(a:version, b:'4.0') >= 0 &&
      cisco_gen_ver_compare(a:version, b:'4.0(4g)') < 0
    )
)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : See vendor.' +
    '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}

audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Cisco UCS Manager', url, version);
