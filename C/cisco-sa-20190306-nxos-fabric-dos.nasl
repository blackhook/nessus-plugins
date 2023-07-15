#TRUSTED 3a6922e3a1cb7c5a935cd15b63a4a879e5b70e142e29fbd031c92a8112bd98c652cf5917f7fc60791e7d07fa0ff3b8d178eaa1216d66596eca409e530b26b29829c8b97f22120d6b933295b002921408d0b97f19f70fd2bec6416f4141ad27999d1f3b94e8dbf852b2f43f268eb86e7a205fe7dfa9db3fdd855b3a3ef39e3140a9f076ca061266d14e6643d1d1d8092b6ce8469a6a357396b988ffc4602f9d55431ae740780d1bc079b48fedda2d49858c6da3f0ab6ed97a203d7df9526821c81dc3350c39ef15d6ad2904545a7a827a32cd63392d34596adb1fb50b428dbdd449c4b50e9878f40e1dbd6a190b33f0a1102b4fb1d6715579106a6dc5a3033657359fc07e32c33eca5e27bb30cc40513fa1157502c2fcf13d92160b008cf62f4b7a0b328ec647d6efaf16f0c25942987fe8584e4f9c13ba2fcad35889dba57908d3a53c76d55f7d1c40ff8c8efb94dc30798ae3c8284fc725de99f2e700eb24d75f8e67db8077bd4c21908162ba07de569f7f504d4e79edb8ed3994050e246068d15166c04b75454f84dfa81d85ba389cfa91de1971fe057519ebff1dee83e721974045bf11ed8333f6a750a811676bb0580c6b9b8fab55c0a08cb9fbc2662c5c659e5fd20f0c1e3d1794f2f7d2befbd5cd5e9282e8465636484d02c0109c4106735ef2656770728eae643d3c2035f64277c9237cb18f2f6c81faa2c117183317
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126477);
  script_version("1.5");
  script_cvs_date("Date: 2019/12/20");

  script_cve_id("CVE-2019-1616");
  script_bugtraq_id(107395);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh99066");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj10176");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj10178");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj10181");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj10183");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190306-nxos-fabric-dos");

  script_name(english:"Cisco NX-OS Software Cisco Fabric Services Denial of Service Vulnerability");
  script_summary(english:"Checks the Cisco NX-OS Software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Cisco device is affected by denial of service (DoS)
    vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco NX-OS Software
is affected by a denial of service (DoS) vulnerability. It exists in Cisco fabric services due to insufficient
validation of Cisco fabric service packets. An unauthenticated, remote attacker can exploit this issue, via sending a
crafted Cisco fabric services packet to an affected device. A successful exploit could allow the attacker to cause a
buffer overflow, resulting in a DoS condition on the device.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190306-nxos-fabric-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c2417bde");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh99066");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj10176");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj10178");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj10181");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj10183");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvh99066 / CSCvj10176 / CSCvj10178 / CSCvj10181 / CSCvj10183.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1616");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

cbi = '';

if ('MDS' >< product_info.device && product_info.model =~ '^90[0-9][0-9]')
  cbi = 'CSCvj10178';
else if ('UCS'>< product_info.device && product_info.model =~ '^6[2-4][0-9][0-9]')
  cbi = 'CSCvj10183';
else if ('Nexus' >< product_info.device)
{
  if (product_info.model =~ '^3[056][0-9][0-9]')
    cbi = 'CSCvh99066, CSCvj10181, CSCvj10176';
  else if (product_info.model =~ '^7[07][0-9][0-9]')
    cbi = 'CSCvj10178';
  else if (product_info.model =~ '^9[05][0-9][0-9]')
    cbi = 'CSCvh99066, CSCvj10176';
 }

if (empty_or_null(cbi))
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '5.0(1a)',
  '5.0(1b)',
  '5.0(3)A1(1)',
  '5.0(3)A1(2)',
  '5.0(3)A1(2a)',
  '5.0(3)U1(1)',
  '5.0(3)U1(1a)',
  '5.0(3)U1(1b)',
  '5.0(3)U1(1c)',
  '5.0(3)U1(1d)',
  '5.0(3)U1(2)',
  '5.0(3)U1(2a)',
  '5.0(3)U2(1)',
  '5.0(3)U2(2)',
  '5.0(3)U2(2a)',
  '5.0(3)U2(2b)',
  '5.0(3)U2(2c)',
  '5.0(3)U2(2d)',
  '5.0(3)U3(1)',
  '5.0(3)U3(2)',
  '5.0(3)U3(2a)',
  '5.0(3)U3(2b)',
  '5.0(3)U4(1)',
  '5.0(3)U5(1)',
  '5.0(3)U5(1a)',
  '5.0(3)U5(1b)',
  '5.0(3)U5(1c)',
  '5.0(3)U5(1d)',
  '5.0(3)U5(1e)',
  '5.0(3)U5(1f)',
  '5.0(3)U5(1g)',
  '5.0(3)U5(1h)',
  '5.0(3)U5(1i)',
  '5.0(3)U5(1j)',
  '5.0(4)',
  '5.0(4b)',
  '5.0(4c)',
  '5.0(4d)',
  '5.0(7)',
  '5.0(8)',
  '5.0(8a)',
  '5.2(1)',
  '5.2(2)',
  '5.2(2a)',
  '5.2(2d)',
  '5.2(2s)',
  '5.2(6)',
  '5.2(6a)',
  '5.2(6b)',
  '5.2(8)',
  '5.2(8a)',
  '5.2(8b)',
  '5.2(8c)',
  '5.2(8d)',
  '5.2(8e)',
  '5.2(8f)',
  '5.2(8g)',
  '5.2(8h)',
  '5.2(8i)',
  '6.0(2)A1(1)',
  '6.0(2)A1(1a)',
  '6.0(2)A1(1b)',
  '6.0(2)A1(1c)',
  '6.0(2)A1(1d)',
  '6.0(2)A1(1e)',
  '6.0(2)A1(1f)',
  '6.0(2)A1(2d)',
  '6.0(2)A3(1)',
  '6.0(2)A3(2)',
  '6.0(2)A3(4)',
  '6.0(2)A4(1)',
  '6.0(2)A4(2)',
  '6.0(2)A4(3)',
  '6.0(2)A4(4)',
  '6.0(2)A4(5)',
  '6.0(2)A4(6)',
  '6.0(2)A6(1)',
  '6.0(2)A6(1a)',
  '6.0(2)A6(2)',
  '6.0(2)A6(2a)',
  '6.0(2)A6(3)',
  '6.0(2)A6(3a)',
  '6.0(2)A6(4)',
  '6.0(2)A6(4a)',
  '6.0(2)A6(5)',
  '6.0(2)A6(5a)',
  '6.0(2)A6(5b)',
  '6.0(2)A6(6)',
  '6.0(2)A6(7)',
  '6.0(2)A6(8)',
  '6.0(2)A7(1)',
  '6.0(2)A7(1a)',
  '6.0(2)A7(2)',
  '6.0(2)A7(2a)',
  '6.0(2)A8(1)',
  '6.0(2)A8(2)',
  '6.0(2)A8(3)',
  '6.0(2)A8(4)',
  '6.0(2)A8(4a)',
  '6.0(2)A8(5)',
  '6.0(2)A8(6)',
  '6.0(2)A8(7)',
  '6.0(2)A8(7a)',
  '6.0(2)A8(7b)',
  '6.0(2)A8(8)',
  '6.0(2)A8(9)',
  '6.0(2)U1(1)',
  '6.0(2)U1(1a)',
  '6.0(2)U1(2)',
  '6.0(2)U1(3)',
  '6.0(2)U1(4)',
  '6.0(2)U2(1)',
  '6.0(2)U2(2)',
  '6.0(2)U2(3)',
  '6.0(2)U2(4)',
  '6.0(2)U2(5)',
  '6.0(2)U2(6)',
  '6.0(2)U3(1)',
  '6.0(2)U3(2)',
  '6.0(2)U3(3)',
  '6.0(2)U3(4)',
  '6.0(2)U3(5)',
  '6.0(2)U3(6)',
  '6.0(2)U3(7)',
  '6.0(2)U3(8)',
  '6.0(2)U3(9)',
  '6.0(2)U4(1)',
  '6.0(2)U4(2)',
  '6.0(2)U4(3)',
  '6.0(2)U4(4)',
  '6.0(2)U5(1)',
  '6.0(2)U5(2)',
  '6.0(2)U5(3)',
  '6.0(2)U5(4)',
  '6.0(2)U6(1)',
  '6.0(2)U6(10)',
  '6.0(2)U6(1a)',
  '6.0(2)U6(2)',
  '6.0(2)U6(2a)',
  '6.0(2)U6(3)',
  '6.0(2)U6(3a)',
  '6.0(2)U6(4)',
  '6.0(2)U6(4a)',
  '6.0(2)U6(5)',
  '6.0(2)U6(5a)',
  '6.0(2)U6(5b)',
  '6.0(2)U6(5c)',
  '6.0(2)U6(6)',
  '6.0(2)U6(7)',
  '6.0(2)U6(8)',
  '6.0(2)U6(9)',
  '6.1(2)',
  '6.1(2)I1(1)',
  '6.1(2)I1(2)',
  '6.1(2)I1(3)',
  '6.1(2)I2(1)',
  '6.1(2)I2(2)',
  '6.1(2)I2(2a)',
  '6.1(2)I2(2b)',
  '6.1(2)I2(3)',
  '6.1(2)I3(1)',
  '6.1(2)I3(2)',
  '6.1(2)I3(3.78)',
  '6.1(2)I3(3)',
  '6.1(2)I3(3a)',
  '6.1(2)I3(3b)',
  '6.1(2)I3(4)',
  '6.1(2)I3(4a)',
  '6.1(2)I3(4b)',
  '6.1(2)I3(4c)',
  '6.1(2)I3(4d)',
  '6.1(2)I3(4e)',
  '6.1(2)I3(5)',
  '6.1(2)I3(5a)',
  '6.1(2)I3(5b)',
  '6.2(1)',
  '6.2(10)',
  '6.2(11)',
  '6.2(11b)',
  '6.2(11c)',
  '6.2(11d)',
  '6.2(11e)',
  '6.2(12)',
  '6.2(13)',
  '6.2(13a)',
  '6.2(13b)',
  '6.2(14)',
  '6.2(15)',
  '6.2(16)',
  '6.2(17)',
  '6.2(18)',
  '6.2(19)',
  '6.2(2)',
  '6.2(20)',
  '6.2(20a)',
  '6.2(21)',
  '6.2(23)',
  '6.2(2a)',
  '6.2(3)',
  '6.2(5)',
  '6.2(5a)',
  '6.2(5b)',
  '6.2(6)',
  '6.2(6a)',
  '6.2(6b)',
  '6.2(7)',
  '6.2(8)',
  '6.2(8a)',
  '6.2(8b)',
  '6.2(9)',
  '6.2(9a)',
  '6.2(9b)',
  '6.2(9c)',
  '7.0(2)I2(2c)',
  '7.0(3)',
  '7.0(3)F1(1)',
  '7.0(3)F2(1)',
  '7.0(3)F2(2)',
  '7.0(3)F3(1)',
  '7.0(3)F3(2)',
  '7.0(3)F3(3)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(4)',
  '7.0(3)I1(1)',
  '7.0(3)I1(1a)',
  '7.0(3)I1(1b)',
  '7.0(3)I1(2)',
  '7.0(3)I1(3)',
  '7.0(3)I1(3a)',
  '7.0(3)I1(3b)',
  '7.0(3)I2(1)',
  '7.0(3)I2(1a)',
  '7.0(3)I2(2)',
  '7.0(3)I2(2a)',
  '7.0(3)I2(2b)',
  '7.0(3)I2(2c)',
  '7.0(3)I2(2d)',
  '7.0(3)I2(2e)',
  '7.0(3)I2(3)',
  '7.0(3)I2(4)',
  '7.0(3)I2(5)',
  '7.0(3)I3(1)',
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
  '7.0(3)I4(8z)',
  '7.0(3)I5(1)',
  '7.0(3)I5(2)',
  '7.0(3)I6(1)',
  '7.0(3)I6(2)',
  '7.0(3)I7(1)',
  '7.0(3)I7(2)',
  '7.0(3)I7(3)',
  '7.0(3)IX1(2)',
  '7.0(3)IX1(2a)',
  '7.2(0)D1(1)',
  '7.2(1)D1(1)',
  '7.2(2)D1(1)',
  '7.2(2)D1(2)',
  '7.3(0)D1(1)',
  '7.3(0)DX(1)',
  '7.3(0)DY(1)',
  '7.3(1)D1(1)',
  '7.3(1)D1(1B)',
  '7.3(1)DY(1)',
  '7.3(2)D1(1)',
  '7.3(2)D1(2)',
  '7.3(2)D1(3)',
  '7.3(2)D1(3a)',
  '7.3(3)D1(1)',
  '8.0(1)',
  '8.0(1)S2',
  '8.1(1)',
  '8.1(1a)',
  '8.1(2)',
  '8.1(2a)',
  '8.2(1)',
  '8.2(2)'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
'port'     , 0,
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , cbi
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
