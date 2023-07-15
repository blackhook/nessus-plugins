#TRUSTED 9000744e030c5d7dd111da3228481cbc78afba0b12e6177d558c91bb20906cc2e53e5d9e55ce49212c8e08b4bbffe8d3bc49e5d821e4779b6a09c51cc94c322e8198999d74617417b5dd0644bd8bf69a54a624f7bafd764e2a4cfc04946b81bd2b5335972c466aaad8b27483ddfd88ec58adc7595526ebde37781c7f0de9ccaf8545011341cdd48a05c0efad3784666e58fdbb5da041f9cffdf8ba3688e93c43b60c74f28eb971538077a48ae3188698c063acdf77104bf6993fb73599d666b6583b764d1fb0fd5138e945c817ab16eda3ae0338e69186101b00594f1ca7372bc5c12ced108978dc61f854eff13c87d79abc4fd751887e7e8c032a14df2aab4b73012bb4888efa5bcab38bdac1cbfab72eaf4438ca01385b1d10d57f3e15e7604ac54eb996a63a1ae46698e6f89a4e3dcb21da1da60eed2addb399c9ab027039c71008609637121ac14e9f1726087001f3cd280e6d2aa90214de64c1e0130e64438e7f52f7a926558966761678ef8826b90576c627aafa143a4e7ab31715d3fcc776a0018b8af2c63871d75fe04bb542b2c61f14f3dde19da4f1b4fd2b817c0a92c69d3a74feeb515e5a20b9fe650be9b7227d659385941791237d1da017712df9288b1ce890b07ecc660749b04d0dc9664ef2613cd2e7e331ef19ba5d01e75c59e7d68d56ef01ad3ab02643017a485614ef3b4b434f476bbf2daca5f26894f5
#
# (C) Tenable Network Security, Inc.
#
include('compat.inc');

if (description)
{
  script_id(128757);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2019/11/27"); 

  script_cve_id("CVE-2019-1963");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn13270");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn23529");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn23531");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn23532");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn23534");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn23535");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn23536");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn23537");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn23538");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190828-fxnxos-snmp-dos");
  script_xref(name:"IAVA", value:"2019-A-0317");

  script_name(english:"Cisco NX-OS Software Authenticated Simple Network Management Protocol Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a denial of service (DoS) vulnerability in 
its SNMP packet processor component due to an insufficent level of user input validation. An authenticated, remote 
attacker can exploit this issue, by sending crafted SNMP packets, to force a restart of the system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190828-fxnxos-snmp-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?355e564b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn13270");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn23529");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn23531");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn23532");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn23534");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn23535");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn23536");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn23537");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn23538");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the linked Cisco bug ID pages");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1963");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('global_settings.inc');
include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

cbi = '';
if('MDS' >< product_info.device && product_info.model =~ '^9[0-9][0-9][0-9]')
  cbi = 'CSCvn23531';
else if ('UCS' >< product_info.device && product_info.model =~ '^6[234][0-9][0-9]')
  cbi = 'CSCvn23535, CSCvn23538';
else if('Firepower' >< product_info.device && product_info.model =~ '^(41|93)[0-9][0-9]')
  cbi = 'CSCvn23536';
else if('Nexus' >< product_info.device)
{
  if(product_info.model =~ '^1000V?')
    cbi = 'CSCvn23532, CSCvn23537';
  else if(product_info.model =~ '^(3[056][0-9][0-9]|9[05][0-9][0-9])')
    cbi = 'CSCvn13270, CSCvn23529';
  else if(product_info.model =~ '^(5[56]|6[0-9])[0-9][0-9]')
    cbi = 'CSCvn23534';
  else if(product_info.model =~ '^7[07][0-9][0-9]')
    cbi = 'CSCvn23531';
}
else audit(AUDIT_HOST_NOT, 'affected');

version_list = make_list(
  '5.0(4b)',
  '5.0(4c)',
  '5.0(4d)',
  '5.0(7)',
  '5.0(8)',
  '5.0(8a)',
  '5.2(1)',
  '5.2(3a)',
  '5.2(4)',
  '5.2(5)',
  '5.2(7)',
  '5.2(9)',
  '5.2(3)',
  '5.2(9a)',
  '5.2(2s)',
  '5.2(6)',
  '5.2(6b)',
  '5.2(8)',
  '5.2(8a)',
  '5.2(6a)',
  '5.2(8b)',
  '5.2(8c)',
  '5.2(8d)',
  '5.2(8e)',
  '5.2(8f)',
  '5.2(8g)',
  '5.2(8h)',
  '5.2(8i)',
  '6.1(1)',
  '6.1(2)',
  '6.1(3)',
  '6.1(4)',
  '6.1(4a)',
  '6.1(5)',
  '4.2(1)SV1(4)',
  '4.2(1)SV1(4a)',
  '4.2(1)SV1(4b)',
  '4.2(1)SV1(5.1)',
  '4.2(1)SV1(5.1a)',
  '4.2(1)SV2(1.1)',
  '4.2(1)SV2(2.1)',
  '4.2(1)SV2(2.1a)',
  '4.2(1)SV2(2.2)',
  '4.2(1)SV2(2.3)',
  '5.0(2)N2(1a)',
  '5.0(3)N1(1c)',
  '5.0(3)N1(1)',
  '5.0(3)N1(1a)',
  '5.0(3)N1(1b)',
  '5.0(3)N2(1)',
  '5.0(3)N2(2)',
  '5.0(3)N2(2a)',
  '5.0(3)N2(2b)',
  '5.1(3)N1(1)',
  '5.1(3)N1(1a)',
  '5.1(3)N2(1)',
  '5.1(3)N2(1a)',
  '5.1(3)N2(1b)',
  '5.1(3)N2(1c)',
  '5.2(1)N1(1)',
  '5.2(1)N1(1a)',
  '5.2(1)N1(1b)',
  '5.2(1)N1(2)',
  '5.2(1)N1(2a)',
  '5.2(1)N1(3)',
  '5.2(1)N1(4)',
  '5.2(1)N1(5)',
  '5.2(1)N1(6)',
  '5.2(1)N1(7)',
  '5.2(1)N1(8a)',
  '5.2(1)N1(8)',
  '5.2(1)N1(8b)',
  '5.2(1)N1(9)',
  '5.2(1)N1(9a)',
  '5.2(1)N1(9b)',
  '5.2(1)SM1(5.1)',
  '5.2(1)SM1(5.2)',
  '5.2(1)SM1(5.2a)',
  '5.2(1)SM1(5.2b)',
  '5.2(1)SM1(5.2c)',
  '5.2(1)SM3(1.1)',
  '5.2(1)SM3(1.1a)',
  '5.2(1)SM3(1.1b)',
  '5.2(1)SM3(1.1c)',
  '5.2(1)SM3(2.1)',
  '5.2(1)SV3(1.4)',
  '5.2(1)SV3(1.1)',
  '5.2(1)SV3(1.3)',
  '5.2(1)SV3(1.5a)',
  '5.2(1)SV3(1.5b)',
  '5.2(1)SV3(1.6)',
  '5.2(1)SV3(1.10)',
  '5.2(1)SV3(1.15)',
  '5.2(1)SV3(2.1)',
  '5.2(1)SV3(2.5)',
  '5.2(1)SV3(2.8)',
  '5.2(1)SV3(3.1)',
  '5.2(1)SV3(1.2)',
  '5.2(1)SV3(1.4b)',
  '5.2(1)SV3(3.15)',
  '5.2(1)SV3(4.1)',
  '6.0(1)',
  '6.0(2)',
  '6.0(3)',
  '6.0(4)',
  '6.0(2)N1(1)',
  '6.0(2)N1(2)',
  '6.0(2)N1(2a)',
  '6.0(2)N1(1a)',
  '6.0(2)N2(1)',
  '6.0(2)N2(1b)',
  '6.0(2)N2(2)',
  '6.0(2)N2(3)',
  '6.0(2)N2(4)',
  '6.0(2)N2(5)',
  '6.0(2)N2(5a)',
  '6.0(2)N2(6)',
  '6.0(2)N2(7)',
  '6.0(2)N2(5b)',
  '6.2(2)',
  '6.2(2a)',
  '6.2(6)',
  '6.2(6b)',
  '6.2(8)',
  '6.2(8a)',
  '6.2(8b)',
  '6.2(10)',
  '6.2(12)',
  '6.2(18)',
  '6.2(16)',
  '6.2(14b)',
  '6.2(14)',
  '6.2(14a)',
  '6.2(6a)',
  '6.2(20)',
  '6.2(1)',
  '6.2(3)',
  '6.2(5)',
  '6.2(5a)',
  '6.2(5b)',
  '6.2(7)',
  '6.2(9)',
  '6.2(9a)',
  '6.2(9b)',
  '6.2(9c)',
  '6.2(11)',
  '6.2(11b)',
  '6.2(11c)',
  '6.2(11d)',
  '6.2(11e)',
  '6.2(13)',
  '6.2(13a)',
  '6.2(13b)',
  '6.2(15)',
  '6.2(17)',
  '6.2(19)',
  '6.2(21)',
  '6.2(23)',
  '6.2(20a)',
  '6.2(25)',
  '6.2(17a)',
  '6.2(27)',
  '7.0(0)N1(1)',
  '7.0(1)N1(1)',
  '7.0(2)N1(1)',
  '7.0(3)F1(1)',
  '7.0(3)F2(1)',
  '7.0(3)F2(2)',
  '7.0(3)F3(1)',
  '7.0(3)F3(2)',
  '7.0(3)F3(3)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(4)',
  '7.0(3)F3(3c)',
  '7.0(3)F3(5)',
  '7.0(3)I4(1)',
  '7.0(3)I4(2)',
  '7.0(3)I4(3)',
  '7.0(3)I4(4)',
  '7.0(3)I4(5)',
  '7.0(3)I4(6)',
  '7.0(3)I4(7)',
  '7.0(3)I4(8)',
  '7.0(3)I4(8a)',
  '7.0(3)I4(8b)',
  '7.0(3)I4(1t)',
  '7.0(3)I4(6t)',
  '7.0(3)I5(1)',
  '7.0(3)I5(2)',
  '7.0(3)I5(3)',
  '7.0(3)I5(3a)',
  '7.0(3)I5(3b)',
  '7.0(3)I6(1)',
  '7.0(3)I6(2)',
  '7.0(3)I7(1)',
  '7.0(3)I7(2)',
  '7.0(3)I7(3)',
  '7.0(3)I7(4)',
  '7.0(3)I7(5)',
  '7.0(3)I7(5a)',
  '7.0(3)I7(3z)',
  '7.0(3)N1(1)',
  '7.0(4)N1(1)',
  '7.0(4)N1(1a)',
  '7.0(5)N1(1)',
  '7.0(5)N1(1a)',
  '7.0(6)N1(1)',
  '7.0(6)N1(4s)',
  '7.0(6)N1(3s)',
  '7.0(6)N1(2s)',
  '7.0(7)N1(1)',
  '7.0(7)N1(1b)',
  '7.0(7)N1(1a)',
  '7.0(8)N1(1)',
  '7.0(8)N1(1a)',
  '7.1(0)N1(1a)',
  '7.1(0)N1(1b)',
  '7.1(0)N1(1)',
  '7.1(1)N1(1)',
  '7.1(1)N1(1a)',
  '7.1(2)N1(1)',
  '7.1(2)N1(1a)',
  '7.1(3)N1(1)',
  '7.1(3)N1(2)',
  '7.1(3)N1(5)',
  '7.1(3)N1(4)',
  '7.1(3)N1(3)',
  '7.1(3)N1(2a)',
  '7.1(4)N1(1)',
  '7.1(4)N1(1d)',
  '7.1(4)N1(1c)',
  '7.1(4)N1(1a)',
  '7.1(5)N1(1)',
  '7.2(0)D1(1)',
  '7.2(0)N1(1)',
  '7.2(1)D1(1)',
  '7.2(1)N1(1)',
  '7.2(2)D1(2)',
  '7.2(2)D1(1)',
  '7.2(2)D1(3)',
  '7.2(2)D1(4)',
  '7.3(0)D1(1)',
  '7.3(0)DX(1)',
  '7.3(0)DY(1)',
  '7.3(0)N1(1)',
  '7.3(0)N1(1b)',
  '7.3(0)N1(1a)',
  '7.3(1)D1(1)',
  '7.3(1)DY(1)',
  '7.3(1)N1(1)',
  '7.3(2)D1(1)',
  '7.3(2)D1(2)',
  '7.3(2)D1(3)',
  '7.3(2)D1(3a)',
  '7.3(2)N1(1)',
  '7.3(2)N1(1b)',
  '7.3(2)N1(1c)',
  '7.3(3)N1(1)',
  '8.0(1)',
  '8.1(1)',
  '8.1(2)',
  '8.1(2a)',
  '8.1(1a)',
  '8.1(1b)',
  '8.2(1)',
  '8.2(2)',
  '8.3(1)',
  '9.2(1)',
  '9.2(2)',
  '9.2(2t)',
  '7.3(4)N1(1)',
  '7.3(4)N1(1a)',
  '7.3(3)D1(1)',
  '7.0(3)IA7(1)',
  '7.0(3)IA7(2)',
  '7.0(3)IC4(4)',
  '7.0(3)IM3(1)',
  '7.0(3)IM3(2)',
  '7.0(3)IM3(2a)',
  '7.0(3)IM3(2b)',
  '7.0(3)IM3(3)',
  '7.0(3)IM7(2)',
  '5.2(1)SK3(1.1)',
  '5.2(1)SK3(2.1)',
  '5.2(1)SK3(2.2)',
  '5.2(1)SK3(2.2b)',
  '5.2(1)SK3(2.1a)'
);

workarounds = make_list(CISCO_WORKAROUNDS['snmp']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , cbi
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
