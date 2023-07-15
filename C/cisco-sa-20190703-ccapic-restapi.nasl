#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(126645);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/03");

  script_cve_id("CVE-2019-1889");
  script_bugtraq_id(109035);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp64857");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190703-ccapic-restapi");
  script_xref(name:"IAVA", value:"2019-A-0218-S");

  script_name(english:"Cisco Application Policy Infrastructure Controller REST API Privilege Escalation Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Application Policy Infrastructure Controller (APIC) is affected by a
privilege escalation vulnerability in the REST API. An authenticated, remote attacker could exploit this, via a
malicious software upload using the REST API, to gain root access to the system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190703-ccapic-restapi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c3ac97d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp64857");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp64857");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1889");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:application_policy_infrastructure_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:application_policy_infrastructure_controller_firmware");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_apic_version.nbin");
  script_require_keys("installed_sw/Cisco APIC Software");

  exit(0);
}

include('audit.inc');
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
  fix ='3.2(9b), 4.1(2g)';
}
else if (version =~ "^3\.2([^0-9]|$)"){
  fix = '3.2(9b)';
  if (cisco_gen_ver_compare(a:version, b:fix) >= 0)
    audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
}
else if (version =~ "^4\.1([^0-9]|$)") {
  fix = '4.1(2g)';
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
