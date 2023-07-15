#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139324);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/07");

  script_cve_id("CVE-2019-1682");
  script_bugtraq_id(108129);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn09779");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190501-apic-priv-escalation");

  script_name(english:"Cisco Application Policy Infrastructure Controller Privilege Escalation (cisco-sa-20190501-apic-priv-escalation)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Application Policy Infrastructure Controller (APIC) is affected by a
vulnerability in the FUSE filesystem functionality. This is due to insufficient input validation of CLI commands.
An authenticated, local attacker can exploit this by alter certain definitions in a affected file, allowing them
to execute commands and gain root privilages. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190501-apic-priv-escalation
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?55ee56eb");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn09779");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvn09779");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1682");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:application_policy_infrastructure_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:application_policy_infrastructure_controller_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_apic_version.nbin");
  script_require_keys("installed_sw/Cisco APIC Software");

  exit(0);
}

include('cisco_func.inc');
include('http.inc');
include('install_func.inc');

app = 'Cisco APIC Software';
get_install_count(app_name:app, exit_if_zero:TRUE);
port = get_http_port(default:443);

install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);
version = install['version'];
dir = install['path'];
install_url = build_url(port:port, qs:dir);

if (version =~ "^([0-2]([^0-9]|$))|(3($|\.[01]($|[^0-9])))") {
  fix ='3.2(6i), 4.1(1i)';
}
else if (version =~ "^3\.[012]([^0-9]|$)"){
  fix = '3.2(6i)';
  if (cisco_gen_ver_compare(a:version, b:fix) >= 0)
    audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
}
else if (version =~ "^4\.[01]([^0-9]|$)") {
  fix = '4.1(1i)';
  if (cisco_gen_ver_compare(a:version, b:fix) >= 0)
    audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);

report = '\n  URL               : ' + install_url +
         '\n  Installed version : ' + version +
         '\n  Fixed version     : ' + fix + ' or later' +
         '\n';
security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);