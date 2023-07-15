#TRUSTED 81e78cf516397353c6f446fab9eb13f9fd256cb76c5a7b41daef978911666c8d0445f400bb6818d48323ad177c3644a1c24595648ce66a0b05494df5c7f1b01f32c1808725c87fb5c19e9e80fbfbc2822690b434c1db80ac1b1b4e69ca7f5a0056cbc31fe44e0140a5219ce97d57ee8dab63ac51d6045f828605ff52e947050e558a2ff4203be68c3b75298e1ef7caf042915fd4fe781fd50f663ed916ffdbbc234be7b91383a3b4a1f817683aaa7f4c35d4ffcb7b7399b2c518f91ebb521b97d1761b93b59604de6462d9e875d2b33c164cd0cb9dcb14ecbadbc2e67272671b4ca1d2baedcbb054cff98926882464963a8eb22cd01e9dacf21ae2c041edf540a65192c1e0314eeac07ef06e7a52a182354bc167ba562c89f77c1ae8f5f669b262b21eac31e2565d6a1768a707c4ac0ebcf0790b626e402ab51f3b0332ef35b2863628d48fa08285005ca97bd0d5e7db8d6a1ef52e9900cca02f3e3c3182f2985bd9500e4d523ea06223b9b1a93e6e323a67c3a41d99594e99cb62a527a99a82eafea85714faa3af98344625edd84c0494e0aef6db828167c9ab588feaf13c1f748a4302eb51a6227bbc616701948de7fd094ce6d5439f26ec26d08023fad81b174a3c43c28a65b80ca0c64971442223280fa3a0b5b7a7771d59545949fbeccd9b8e91485872598e4fc44abdcad88ddfdfc44c725c093b1277799130d317440c
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134226);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/03");

  script_cve_id("CVE-2018-0291");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw99630");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj67977");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg71290");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-nxossnmp");
  script_xref(name:"IAVA", value:"2020-A-0127");

  script_name(english:"Cisco NX-OS Software Authenticated Simple Network Management Protocol DoS (cisco-sa-20180620-nxossnmp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a denial of service (DoS) vulnerability in
the Simple Network Management Protocol (SNMP) input packet processor due to improper validation of SNMP protocol data
units (PDUs) in SNMP packets. An authenticated, remote attacker can exploit this, by sending a crafted SNMP packet to
an affected device, in order to cause the SNMP application to restart unexpectedly.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-nxossnmp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20dbad53");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-67770");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuw99630");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj67977");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg71290");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed / recommended version referenced in Cisco Security Advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0291");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');


product_info = cisco::get_product_info(name:'Cisco NX-OS Software');
bugIDs = NULL;

if (('UCS' >< product_info['device']) && (product_info['model'] =~ '^6[1-3][0-9][0-9]'))
{
  bugIDs = 'CSCvg71290';
  vuln_ranges = [
    {'min_ver': '0.0', 'fix_ver': '3.2(2b)'}
  ];
}
else if ('Nexus' >< product_info['device'])
{
  if (product_info['model'] =~ '^30[0-9][0-9]')
    bugIDs = 'CSCuw99630';
  else if (product_info['model'] =~ '^35[0-9][0-9]')
    bugIDs = 'CSCuw99630';
  else if (product_info['model'] =~ '^2[0-9][0-9][0-9]' ||
           product_info['model'] =~ '^5[56][0-9][0-9]'  ||
           product_info['model'] =~ '^6[0-9][0-9][0-9]')
    bugIDs = 'CSCuw99630';
  else if (product_info['model'] =~ '^7[07][0-9][0-9]')
    bugIDs = 'CSCuw99630';
  else if (product_info['model'] =~ '^90[0-9][0-9]')
    bugIDs = 'CSCuw99630';
  else if (product_info['model'] =~ '^95[0-9][0-9]')
    bugIDs = 'CSCuw99630, CSCvj67977';
  else if (product_info['model'] =~ '^36[0-9][0-9]i')
    bugIDs = 'CSCuw99630, CSCvj67977';
}

if (isnull(bugIDs)) audit(AUDIT_HOST_NOT, 'affected');

workarounds = make_list(CISCO_WORKAROUNDS['snmp']);
workaround_params = make_list();

if (empty_or_null(vuln_ranges))
  version_list = make_list(
    '5.2(1)',
    '5.2(3a)',
    '5.2(4)',
    '5.2(5)',
    '5.2(7)',
    '5.2(9)',
    '5.2(3)',
    '5.2(9a)',
    '6.1(1)',
    '6.1(2)',
    '6.1(3)',
    '6.1(4)',
    '6.1(4a)',
    '6.1(5)',
    '6.1(3)S5',
    '6.1(3)S6',
    '6.1(5a)',
    '4.2(1)N1(1)',
    '4.2(1)N2(1)',
    '4.2(1)N2(1a)',
    '5.0(2)N1(1)',
    '5.0(2)N2(1)',
    '5.0(2)N2(1a)',
    '5.0(3)A1(1)',
    '5.0(3)A1(2)',
    '5.0(3)A1(2a)',
    '5.0(3)N1(1c)',
    '5.0(3)N1(1)',
    '5.0(3)N1(1a)',
    '5.0(3)N1(1b)',
    '5.0(3)N2(1)',
    '5.0(3)N2(2)',
    '5.0(3)N2(2a)',
    '5.0(3)N2(2b)',
    '5.0(3)U1(1)',
    '5.0(3)U1(1a)',
    '5.0(3)U1(1b)',
    '5.0(3)U1(1d)',
    '5.0(3)U1(2)',
    '5.0(3)U1(2a)',
    '5.0(3)U1(1c)',
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
    '6.0(1)',
    '6.0(2)',
    '6.0(3)',
    '6.0(4)',
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
    '6.0(2)N1(1)',
    '6.0(2)N1(2)',
    '6.0(2)N1(2a)',
    '6.0(2)N2(1)',
    '6.0(2)N2(1b)',
    '6.0(2)N2(2)',
    '6.0(2)N2(3)',
    '6.0(2)N2(4)',
    '6.0(2)N2(5)',
    '6.0(2)N2(5a)',
    '6.0(2)N2(6)',
    '6.0(2)N2(7)',
    '6.0(2)U1(1)',
    '6.0(2)U1(2)',
    '6.0(2)U1(1a)',
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
    '6.0(2)U6(2)',
    '6.0(2)U6(3)',
    '6.0(2)U6(4)',
    '6.0(2)U6(5)',
    '6.0(2)U6(6)',
    '6.0(2)U6(7)',
    '6.0(2)U6(8)',
    '6.0(2)U6(1a)',
    '6.0(2)U6(2a)',
    '6.0(2)U6(3a)',
    '6.0(2)U6(4a)',
    '6.0(2)U6(5a)',
    '6.0(2)U6(5b)',
    '6.0(2)U6(5c)',
    '6.0(2)U6(9)',
    '6.0(2)U6(10)',
    '6.1(2)I1(3)',
    '6.1(2)I2(1)',
    '6.1(2)I2(2)',
    '6.1(2)I2(2a)',
    '6.1(2)I2(3)',
    '6.1(2)I2(2b)',
    '6.1(2)I3(1)',
    '6.1(2)I3(2)',
    '6.1(2)I3(3)',
    '6.1(2)I3(3.78)',
    '6.1(2)I3(4)',
    '6.1(2)I3(3a)',
    '6.1(2)I3(4a)',
    '6.1(2)I3(4b)',
    '6.1(2)I3(4c)',
    '6.1(2)I3(4d)',
    '6.1(2)I3(4e)',
    '6.1(2)I3(5)',
    '6.1(2)I3(5a)',
    '6.1(2)I3(5b)',
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
    '7.0(3)',
    '7.0(0)N1(1)',
    '7.0(1)N1(1)',
    '7.0(2)I2(2c)',
    '7.0(2)N1(1)',
    '7.0(2)N1(1a)',
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
    '7.0(3)I2(2a)',
    '7.0(3)I2(2b)',
    '7.0(3)I2(2c)',
    '7.0(3)I2(2d)',
    '7.0(3)I2(2e)',
    '7.0(3)I2(3)',
    '7.0(3)I2(4)',
    '7.0(3)I2(5)',
    '7.0(3)I2(1)',
    '7.0(3)I2(1a)',
    '7.0(3)I2(2)',
    '7.0(3)I3(1)',
    '7.0(3)I5(1)',
    '7.0(3)I5(2)',
    '7.0(3)I6(1)',
    '7.0(3)I6(2)',
    '7.0(3)IX1(2)',
    '7.0(3)IX1(2a)',
    '7.0(3)N1(1)',
    '7.0(4)N1(1)',
    '7.0(4)N1(1a)',
    '7.0(5)N1(1)',
    '7.0(5)N1(1a)',
    '7.0(6)N1(1)',
    '7.0(6)N1(4s)',
    '7.0(6)N1(3s)',
    '7.0(6)N1(2s)',
    '7.0(6)N1(1c)',
    '7.0(7)N1(1)',
    '7.0(7)N1(1b)',
    '7.0(7)N1(1a)',
    '7.0(8)N1(1)',
    '7.0(8)N1(1a)',
    '7.1(0)N1(1a)',
    '7.1(0)N1(1b)',
    '7.1(0)N1(2)',
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
    '7.1(3)N1(1b)',
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
    '7.3(0)D1(1)',
    '7.3(0)DX(1)',
    '7.3(0)N1(1)',
    '7.3(0)N1(1b)',
    '7.3(0)N1(1a)',
    '7.3(1)D1(1B)',
    '7.3(1)D1(1)',
    '7.3(1)N1(0.1)',
    '7.3(1)N1(1)',
    '7.3(2)D1(1A)',
    '7.3(2)D1(1)',
    '7.3(2)D1(2)',
    '7.3(2)N1(1)',
    '8.0(1)',
    '8.1(1)',
    '8.1(2)',
    '8.1(2a)',
    '8.2(1)',
    '8.2(2)'
  );

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , bugIDs,
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  vuln_ranges:vuln_ranges
);
