#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(141192);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id("CVE-2020-3161");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz03016");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs78272");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs78441");
  script_xref(name:"CISCO-SA", value:"cisco-sa-voip-phones-rce-dos-rB6EeRXs");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Cisco IP Phones Web Server RCE and DOS (cisco-sa-voip-phones-rce-dos-rB6EeRXs)");

  script_set_attribute(attribute:"synopsis", value:
"The remote IP phone has multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability and remote code execution (RCE) exists in Cisco IP Phones due 
to a lack of proper input validation of HTTP requests. An unauthenticated attacker can exploit this 
vulnerability by sending a crafted HTTP request to the web server of a targeted device. A successful exploit 
could allow the attacker to remotely execute code with root privileges or cause a reload of an affected IP phone, 
resulting in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-voip-phones-rce-dos-rB6EeRXs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f2eef1cf");
  script_set_attribute(attribute:"solution", value:
"Apply the fix referenced in the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3161");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:cisco:ip_phone");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:ip_phone");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ip_phone_sip_detect.nbin");
  script_require_keys("installed_sw/Cisco IP Phone");
  script_require_ports("Services/sip", "Services/udp/sip");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

app = 'Cisco IP Phone';

detected_on = get_kb_list('installed_sw/*/Cisco IP Phone/service/*/SIP/Banner');

report = '';

foreach item(keys(detected_on))
{
  portproto = pregmatch(string:item, pattern:'installed_sw/([0-9]+)/Cisco IP Phone/service/([a-z]{3})/SIP/Banner');
  if (!empty_or_null(portproto))
  {
    port = portproto[1];
    proto = portproto[2];
    app_info = vcf::cisco_ip_phone::get_app_info(app:app, port:port, proto:proto);

    mod = app_info['model'];

    #  IP Phone 7811, 7821, 7841, 7861 Desktop Phones	
    #  IP Phone 8811, 8841, 8845, 8851, 8861, 8865 Desktop Phones
    models = {
      '7811'      : { 'constraints': [{'fixed_version' : '11.7.1',  'fixed_display' : '11.7.1, Refer to Cisco Bug ID: CSCuz03016'}]},
      '7821'      : { 'constraints': [{'fixed_version' : '11.7.1',  'fixed_display' : '11.7.1, Refer to Cisco Bug ID: CSCuz03016'}]},
      '7841'      : { 'constraints': [{'fixed_version' : '11.7.1',  'fixed_display' : '11.7.1, Refer to Cisco Bug ID: CSCuz03016'}]},
      '7861'      : { 'constraints': [{'fixed_version' : '11.7.1',  'fixed_display' : '11.7.1, Refer to Cisco Bug ID: CSCuz03016'}]},
      '8811'      : { 'constraints': [{'fixed_version' : '11.7.1',  'fixed_display' : '11.7.1, Refer to Cisco Bug ID: CSCuz03016'}]},
      '8841'      : { 'constraints': [{'fixed_version' : '11.7.1',  'fixed_display' : '11.7.1, Refer to Cisco Bug ID: CSCuz03016'}]},
      '8845'      : { 'constraints': [{'fixed_version' : '11.7.1',  'fixed_display' : '11.7.1, Refer to Cisco Bug ID: CSCuz03016'}]},
      '8851'      : { 'constraints': [{'fixed_version' : '11.7.1',  'fixed_display' : '11.7.1, Refer to Cisco Bug ID: CSCuz03016'}]},
      '8861'      : { 'constraints': [{'fixed_version' : '11.7.1',  'fixed_display' : '11.7.1, Refer to Cisco Bug ID: CSCuz03016'}]},
      '8865'      : { 'constraints': [{'fixed_version' : '11.7.1',  'fixed_display' : '11.7.1, Refer to Cisco Bug ID: CSCuz03016'}]},
      '8821'      : { 'constraints': [{'fixed_version' : '11.0(5)SR3',  'fixed_display' : '11.0(5)SR3, Refer to Cisco Bug ID: CSCvs78272'}]},
      '8831'      : { 'constraints': [{'fixed_version' : '10.3(1)SR6',  'fixed_display' : '10.3(1)SR6, Refer to Cisco Bug ID: CSCvs78441'}]}
    };

    report += vcf::cisco_ip_phone::check_version(app_info:app_info, constraints:models[app_info.model]['constraints']);
  }
}

if (empty_or_null(report))
  audit(AUDIT_HOST_NOT, 'affected');

security_report_v4(port:port, proto:proto, severity:SECURITY_HOLE, extra:report);
