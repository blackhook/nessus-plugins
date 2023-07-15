#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172375);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id("CVE-2023-20078", "CVE-2023-20079");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc78400");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd39132");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd40474");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd40489");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd40494");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ip-phone-cmd-inj-KMFynVcP");

  script_name(english:"Cisco IP Phones < 11.3.7SR1 Multiple Vulnerabilities (cisco-sa-ip-phone-cmd-inj-KMFynVcP)");

  script_set_attribute(attribute:"synopsis", value:
"The remote IP phone is potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Multiple vulnerabilities in the web-based management interface of certain Cisco IP Phones could allow an
unauthenticated, remote attacker to execute arbitrary code or cause a denial of service (DoS) condition. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ip-phone-cmd-inj-KMFynVcP
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?51c3acc8");
  script_set_attribute(attribute:"solution", value:
"Apply the fix referenced in the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20078");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/09");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:cisco:ip_phone");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:ip_phone");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ip_phone_sip_detect.nbin");
  script_require_keys("installed_sw/Cisco IP Phone", "Settings/ParanoidReport");
  script_require_ports("Services/sip", "Services/udp/sip");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

# Remote detection can't check fo SR or multiplatform firmware
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var app = 'Cisco IP Phone';

var detected_on = get_kb_list('installed_sw/*/Cisco IP Phone/service/*/SIP/Banner');

var report = '';

foreach item(keys(detected_on))
{
  var portproto = pregmatch(string:item, pattern:'installed_sw/([0-9]+)/Cisco IP Phone/service/([a-z]{3})/SIP/Banner');
  if (!empty_or_null(portproto))
  {
    var port = portproto[1];
    var proto = portproto[2];
    var app_info = vcf::cisco_ip_phone::get_app_info(app:app, port:port, proto:proto);

    var mod = app_info['model'];

    var models = {
      '6800'      : { 'constraints': [{'fixed_version' : '11.3.8', 'fixed_display': '11.3.7SR1'}]},
      '7800'      : { 'constraints': [{'fixed_version' : '11.3.8', 'fixed_display': '11.3.7SR1'}]},
      '8800'      : { 'constraints': [{'fixed_version' : '11.3.8', 'fixed_display': '11.3.7SR1'}]},
      '8831'      : { 'constraints': [{'fixed_version' : '999.999', 'fixed_display': 'See vendor advisory'}]},
      '7900'      : { 'constraints': [{'fixed_version' : '999.999', 'fixed_display': 'See vendor advisory'}]}
      };
    report += vcf::cisco_ip_phone::check_version(app_info:app_info, constraints:models[app_info.model]['constraints']);
  }
}

if (empty_or_null(report))
  audit(AUDIT_HOST_NOT, 'affected');

security_report_v4(port:port, proto:proto, severity:SECURITY_HOLE, extra:report);
