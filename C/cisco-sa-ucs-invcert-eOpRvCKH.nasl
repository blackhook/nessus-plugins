##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146450);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/17");

  script_cve_id("CVE-2021-1354");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw35850");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ucs-invcert-eOpRvCKH");
  script_xref(name:"IAVA", value:"2021-A-0075");

  script_name(english:"Cisco Unified Computing System (UCS) Central Software Improper Certificate Validation (cisco-sa-ucs-invcert-eOpRvCKH)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unified Computing System Central Software is affected by an improper
certificate validation vulnerability. An authenticated, adjacent attacker could exploit this, by sending a crafted 
HTTP request to the registration API, to register a rogue Cisco UCSM and gain access to Cisco UCS Central Software 
data and Cisco UCSM inventory data.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ucs-invcert-eOpRvCKH
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bf1e3c29");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw35850");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw35850");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1354");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(295);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:unified_computing_system_central");
  script_set_attribute(attribute:"stig_severity", value:"III");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucs_central_webui_detect.nbin");
  script_require_keys("installed_sw/Cisco UCS Central WebUI");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('cisco_func.inc');
include('http.inc');
include('install_func.inc');

port = get_http_port(default:443);
install = get_single_install(app_name:'Cisco UCS Central WebUI', port:port);
install_url = build_url(port:port, qs:install['path']);
fix = '2.0(1m)';

if (install['version'] == UNKNOWN_VER) 
  audit(AUDIT_UNKNOWN_WEB_APP_VER, 'Cisco UCS Central Software', install_url);

if (cisco_gen_ver_compare(a:install['version'], b:fix) >= 0)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Cisco UCS Central Software', install_url, install['version']);

report = '\n  URL               : ' + install_url +
         '\n  Installed version : ' + install['version'] +
         '\n  Fixed version     : ' + fix + 
         '\n';
security_report_v4(port:0, severity:SECURITY_NOTE, extra:report);