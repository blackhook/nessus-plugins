#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134236);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/10");

  script_cve_id("CVE-2020-3172");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr37150");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200226-fxos-nxos-cdp");
  script_xref(name:"IAVA", value:"2020-A-0086");

  script_name(english:"Cisco UCS Software Cisco Discovery Protocol Arbitrary Code Execution and DoS (cisco-sa-20200226-fxos-nxos-cdp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco UCS Software is affected by a vulnerability in the Cisco Discovery
Protocol feature due to insufficient validation of Cisco Discovery Protocol packet headers. An unauthenticated, adjacent
attacker can exploit this, by sending a crafted Cisco Discovery Protocol packet to a Layer-2 adjacent affected device,
in order to execute arbitrary code as root or cause a denial of service DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be9c7431/");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr37150");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr37150.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3172");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_computing_system");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

app = 'Cisco UCS Manager';
get_install_count(app_name:'cisco_ucs_manager', exit_if_zero:TRUE);

port = get_http_port(default:80);
install = get_single_install(app_name:'cisco_ucs_manager', port:port, exit_if_unknown_ver:TRUE);

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
