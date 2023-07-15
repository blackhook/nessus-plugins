#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(142018);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id("CVE-2020-3111");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96057");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96058");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96059");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96060");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96063");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96064");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96065");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96066");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96067");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96069");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96070");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96071");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96738");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96739");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200205-voip-phones-rce-dos");
  script_xref(name:"CEA-ID", value:"CEA-2020-0016");

  script_name(english:"Cisco IP Phones Web Server RCE and DOS (cisco-sa-20200205-voip-phones-rce-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote IP phone has multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability and remote code execution (RCE) exists in Cisco IP Phones due to missing 
checks when processing Cisco Discovery Protocol messages. An unauthenticated attacker can exploit this 
vulnerability by sending a crafted Cisco Discovery Protocol packet to the targeted IP phone. A successful exploit 
could allow the attacker to remotely execute code with root privileges or cause a reload of an affected IP phone, 
resulting in a denial of service (DoS) condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200205-voip-phones-rce-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?065576a8");
  script_set_attribute(attribute:"solution", value:
"Apply the fix referenced in the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3111");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/28");

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

    #  IP Phone 7832, 8832,  6821, 6841, 6851, 6861, 6871, 7811, 7821, 7841, 7861 
    # 8811, 8841, 8851, 8861, 8845, 8865, 8831

    if (report_paranoia < 2)
    {
      models = {
        '7832'      : { 'constraints': [{'fixed_version' : '12.7(1)',  'fixed_display' : '12.7(1), Refer to Cisco Bug ID: CSCvr96069'}]},
        '8832'      : { 'constraints': [{'fixed_version' : '12.7(1)',  'fixed_display' : '12.7(1), Refer to Cisco Bug ID: CSCvr96071'}]},
        '7811'      : { 'constraints': [{'fixed_version' : '12.7(1)',  'fixed_display' : '12.7(1), Refer to Cisco Bug ID: CSCvr96739'}]},
        '7821'      : { 'constraints': [{'fixed_version' : '12.7(1)',  'fixed_display' : '12.7(1), Refer to Cisco Bug ID: CSCvr96739'}]},
        '7841'      : { 'constraints': [{'fixed_version' : '12.7(1)',  'fixed_display' : '12.7(1), Refer to Cisco Bug ID: CSCvr96739'}]},
        '7861'      : { 'constraints': [{'fixed_version' : '12.7(1)',  'fixed_display' : '12.7(1), Refer to Cisco Bug ID: CSCvr96739'}]},
        '8811'      : { 'constraints': [{'fixed_version' : '12.7(1)',  'fixed_display' : '12.7(1), Refer to Cisco Bug ID: CSCvr96066, CSCvr96069'}]},
        '8841'      : { 'constraints': [{'fixed_version' : '12.7(1)',  'fixed_display' : '12.7(1), Refer to Cisco Bug ID: CSCvr96066, CSCvr96069'}]},
        '8851'      : { 'constraints': [{'fixed_version' : '12.7(1)',  'fixed_display' : '12.7(1), Refer to Cisco Bug ID: CSCvr96066, CSCvr96069'}]},
        '8861'      : { 'constraints': [{'fixed_version' : '12.7(1)',  'fixed_display' : '12.7(1), Refer to Cisco Bug ID: CSCvr96066, CSCvr96069'}]},
        '8845'      : { 'constraints': [{'fixed_version' : '12.7(1)',  'fixed_display' : '12.7(1), Refer to Cisco Bug ID: CSCvr96066, CSCvr96069'}]},
        '8865'      : { 'constraints': [{'fixed_version' : '12.7(1)',  'fixed_display' : '12.7(1), Refer to Cisco Bug ID: CSCvr96066, CSCvr96069'}]},
        '8821'      : { 'constraints': [{'fixed_version' : '11.0(5)SR2',  'fixed_display' : '11.0(5)SR2, Refer to Cisco Bug ID: CSCvr96070'}]},      
        '8831'      : { 'constraints': [{'fixed_version' : '10.3(1)SR6',  'fixed_display' : '10.3(1)SR6, Refer to Cisco Bug ID: CSCvr96738'}]}
       };
    }
    else
    {
      models = { 
        '7832'      : { 'constraints': [{'fixed_version' : '11.3(1)SR1',  'fixed_display' : '11.3(1)SR1, Refer to Cisco Bug ID: CSCvr96060'}]},
        '8832'      : { 'constraints': [{'fixed_version' : '11.3(1)SR1',  'fixed_display' : '11.3(1)SR1, Refer to Cisco Bug ID: CSCvr96064 '}]},
        '7811'      : { 'constraints': [{'fixed_version' : '11.3(1)SR1',  'fixed_display' : '11.3(1)SR1, Refer to Cisco Bug ID: CSCvr96063'}]},
        '7821'      : { 'constraints': [{'fixed_version' : '11.3(1)SR1',  'fixed_display' : '11.3(1)SR1, Refer to Cisco Bug ID: CSCvr96063'}]},
        '7841'      : { 'constraints': [{'fixed_version' : '11.3(1)SR1',  'fixed_display' : '11.3(1)SR1, Refer to Cisco Bug ID: CSCvr96063'}]},
        '7861'      : { 'constraints': [{'fixed_version' : '11.3(1)SR1',  'fixed_display' : '11.3(1)SR1, Refer to Cisco Bug ID: CSCvr96063'}]},
        '6821'      : { 'constraints': [{'fixed_version' : '11.3(1)SR1',  'fixed_display' : '11.3(1)SR1, Refer to Cisco Bug ID: CSCvr96065, CSCvr96067'}]},
        '6841'      : { 'constraints': [{'fixed_version' : '11.3(1)SR1',  'fixed_display' : '11.3(1)SR1, Refer to Cisco Bug ID: CSCvr96065, CSCvr96067'}]},
        '6851'      : { 'constraints': [{'fixed_version' : '11.3(1)SR1',  'fixed_display' : '11.3(1)SR1, Refer to Cisco Bug ID: CSCvr96065, CSCvr96067'}]},
        '6861'      : { 'constraints': [{'fixed_version' : '11.3(1)SR1',  'fixed_display' : '11.3(1)SR1, Refer to Cisco Bug ID: CSCvr96065, CSCvr96067'}]},
        '6871'      : { 'constraints': [{'fixed_version' : '11.3(1)SR1',  'fixed_display' : '11.3(1)SR1, Refer to Cisco Bug ID: CSCvr96065, CSCvr96067'}]},
        '8811'      : { 'constraints': [{'fixed_version' : '11.3(1)SR1',  'fixed_display' : '11.3(1)SR1, Refer to Cisco Bug ID: CSCvr96066, CSCvr96058, CSCvr96059'}]},
        '8841'      : { 'constraints': [{'fixed_version' : '11.3(1)SR1',  'fixed_display' : '11.3(1)SR1, Refer to Cisco Bug ID: CSCvr96066, CSCvr96058, CSCvr96059'}]},
        '8851'      : { 'constraints': [{'fixed_version' : '11.3(1)SR1',  'fixed_display' : '11.3(1)SR1, Refer to Cisco Bug ID: CSCvr96066, CSCvr96058, CSCvr96059'}]},
        '8861'      : { 'constraints': [{'fixed_version' : '11.3(1)SR1',  'fixed_display' : '11.3(1)SR1, Refer to Cisco Bug ID: CSCvr96066, CSCvr96058, CSCvr96059'}]},
        '8845'      : { 'constraints': [{'fixed_version' : '11.3(1)SR1',  'fixed_display' : '11.3(1)SR1, Refer to Cisco Bug ID: CSCvr96066, CSCvr96058, CSCvr96059'}]},
        '8865'      : { 'constraints': [{'fixed_version' : '11.3(1)SR1',  'fixed_display' : '11.3(1)SR1, Refer to Cisco Bug ID: CSCvr96066, CSCvr96058, CSCvr96059'}]}
      };
    }

    report += vcf::cisco_ip_phone::check_version(app_info:app_info, constraints:models[app_info.model]['constraints']);
  }
}

if (empty_or_null(report))
  audit(AUDIT_HOST_NOT, 'affected');

security_report_v4(port:port, proto:proto, severity:SECURITY_HOLE, extra:report);
