#TRUSTED 38de8c75da208c8ab8347f03045a0a56111db2c72623c5e8634f8c34aedb56a009ce96d0fc34b638eaeb0a18d56f6296ee85f82f5f94352bd6f29e3cd4716d1987fe7e96b5eea6f9409ad28bb64454d74e5cfa36014b29a3c9bbd381feb51fc3b4291f9c624aa33fc6bf154ddd7d1b0306f6314a75b1651d86cdc81380c74133e25d666ac02de76dcd775da22d55da4843f9557804322b498f819f068b35ba27697dad2379542d608fa31a393278b5d7d12ce942f776778ac33cc583bd33f200b84e7ecdeffce74f7d01d4d074bff9671ee37b5e0a05e67f9674dcdf97ab2422d953d44245181655d603ac712da828ecfa78de94c94beeb9e5fcdb68adb99c187a72be4fd37b2dbeda3a0c21e3954fa1cd0f67b219c288fe2ba16aa68aa0e900df272f49e0dd65e29c37d7acc9e69a81a9f75b1163b52e7b74c619658de31097eb7115225145e8d38b73f679ca3438bcfdeeca49fd982f107b20f321d2e5e8d537a34c30a8446a64076e29b70c562218397a9e2918813da8db125cdf4d28e4ca2bba099693ad5f86a5c059260cb0ceb1bde2462c48b7ef6fb131a2f2b1d52041de0d1573ce790eb0f03a70ab5e8b70126b710726ab43a3ff79e2e798b1cca510f81fb7882f17f2c0bad2361d85ac57767234242a0de314c4eef8cf209f847199a9d570db07281d23061fa426dc50cbdc61c1dc44c1874a75999b2e54cb46b1b9
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(142423);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/05");

  script_cve_id("CVE-2020-3517");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt39630");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt46835");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt46837");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fxos-nxos-cfs-dos-dAmnymbd");

  script_name(english:"Cisco NX-OS Software Cisco Fabric Services DoS (cisco-sa-fxos-nxos-cfs-dos-dAmnymbd)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco NX-OS Software is affected by a denial of service (DoS) 
vulnerability. It exists in Cisco fabric services due to insufficient error handling of Cisco fabric service messages. 
An unauthenticated, remote attacker can exploit this issue, via sending crafted Cisco fabric service messages to an 
affected device, resulting in a Denial of Service event.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fxos-nxos-cfs-dos-dAmnymbd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?947dee6e");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74239");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt39630");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt46835");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt46837");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvt39630, CSCvt46835, CSCvt46837");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3517");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(476);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

cbi = '';

if ('MDS' >< product_info.device && product_info.model =~ "^90[0-9]{2}")
{
    cbi = 'CSCvt46835';
} 
else if ('Nexus' >< product_info.device)
{
  if (product_info.model =~ "^90[0-9]{2}")
  {
    cbi = 'CSCvt39630';
  } 
  else if (product_info.model =~ "^70[0-9]{2}")
  {
    cbi = 'CSCvt46835';
  } 
  else if (product_info.model =~ "^60[0-9]{2}")
  {
    cbi = 'CSCvt46837';
  } 
  else if (product_info.model =~ "^5[56][0-9]{2}")
  {
    cbi = 'CSCvt46837';
  } 
  else if (product_info.model =~ "^30[0-9]{2}")
  {
    cbi = 'CSCvt39630';
  } 
}

if(cbi == '') audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '9.3(3)',
  '9.3(2)',
  '9.3(1z)',
  '9.3(1)',
  '9.2(4)',
  '9.2(3y)',
  '9.2(3)',
  '9.2(2v)',
  '9.2(2t)',
  '9.2(2)',
  '9.2(1)',
  '8.4(1a)',
  '8.4(1)',
  '8.3(2)',
  '8.3(1)',
  '8.2(5)',
  '8.2(4)',
  '8.2(3)',
  '8.2(2)',
  '8.2(1)',
  '8.1(2a)',
  '8.1(2)',
  '8.1(1b)',
  '8.1(1a)',
  '8.1(1)',
  '8.0(1)',
  '7.3(7)N1(1b)',
  '7.3(7)N1(1a)',
  '7.3(7)N1(1)',
  '7.3(6)N1(1a)',
  '7.3(6)N1(1)',
  '7.3(5)N1(1)',
  '7.3(5)D1(1)',
  '7.3(4)N1(1a)',
  '7.3(4)N1(1)',
  '7.3(4)D1(1)',
  '7.3(3)N1(1)',
  '7.3(3)D1(1)',
  '7.3(2)N1(1c)',
  '7.3(2)N1(1b)',
  '7.3(2)N1(1)',
  '7.3(2)D1(3a)',
  '7.3(2)D1(3)',
  '7.3(2)D1(2)',
  '7.3(2)D1(1d)',
  '7.3(2)D1(1)',
  '7.3(1)N1(1)',
  '7.3(1)DY(1)',
  '7.3(1)D1(1)',
  '7.3(0)N1(1b)',
  '7.3(0)N1(1a)',
  '7.3(0)N1(1)',
  '7.3(0)DY(1)',
  '7.3(0)DX(1)',
  '7.3(0)D1(1)',
  '7.2(2)D1(4)',
  '7.2(2)D1(3)',
  '7.2(2)D1(2)',
  '7.2(2)D1(1)',
  '7.2(1)N1(1)',
  '7.2(1)D1(1)',
  '7.2(0)N1(1)',
  '7.2(0)D1(1)',
  '7.1(5)N1(1b)',
  '7.1(5)N1(1)',
  '7.1(4)N1(1d)',
  '7.1(4)N1(1c)',
  '7.1(4)N1(1a)',
  '7.1(4)N1(1)',
  '7.1(3)N1(5)',
  '7.1(3)N1(4)',
  '7.1(3)N1(3)',
  '7.1(3)N1(2a)',
  '7.1(3)N1(2)',
  '7.1(3)N1(1)',
  '7.1(2)N1(1a)',
  '7.1(2)N1(1)',
  '7.1(1)N1(1a)',
  '7.1(1)N1(1)',
  '7.1(0)N1(1b)',
  '7.1(0)N1(1a)',
  '7.1(0)N1(1)',
  '7.0(8)N1(1a)',
  '7.0(8)N1(1)',
  '7.0(7)N1(1b)',
  '7.0(7)N1(1a)',
  '7.0(7)N1(1)',
  '7.0(6)N1(4s)',
  '7.0(6)N1(3s)',
  '7.0(6)N1(2s)',
  '7.0(6)N1(1)',
  '7.0(5)N1(1a)',
  '7.0(5)N1(1)',
  '7.0(4)N1(1a)',
  '7.0(4)N1(1)',
  '7.0(3)N1(1)',
  '7.0(3)IX1(2a)',
  '7.0(3)IX1(2)',
  '7.0(3)IM7(2)',
  '7.0(3)IM3(3)',
  '7.0(3)IM3(2b)',
  '7.0(3)IM3(2a)',
  '7.0(3)IM3(2)',
  '7.0(3)IM3(1)',
  '7.0(3)IC4(4)',
  '7.0(3)IA7(2)',
  '7.0(3)IA7(1)',
  '7.0(3)I7(8)',
  '7.0(3)I7(7)',
  '7.0(3)I7(6z)',
  '7.0(3)I7(6)',
  '7.0(3)I7(5a)',
  '7.0(3)I7(5)',
  '7.0(3)I7(4)',
  '7.0(3)I7(3z)',
  '7.0(3)I7(3)',
  '7.0(3)I7(2)',
  '7.0(3)I7(1)',
  '7.0(3)I6(2)',
  '7.0(3)I6(1)',
  '7.0(3)I5(3b)',
  '7.0(3)I5(3a)',
  '7.0(3)I5(3)',
  '7.0(3)I5(2)',
  '7.0(3)I5(1)',
  '7.0(3)I4(9)',
  '7.0(3)I4(8z)',
  '7.0(3)I4(8b)',
  '7.0(3)I4(8a)',
  '7.0(3)I4(8)',
  '7.0(3)I4(7)',
  '7.0(3)I4(6t)',
  '7.0(3)I4(6)',
  '7.0(3)I4(5)',
  '7.0(3)I4(4)',
  '7.0(3)I4(3)',
  '7.0(3)I4(2)',
  '7.0(3)I4(1t)',
  '7.0(3)I4(1)',
  '7.0(3)I3(1)',
  '7.0(3)I2(5)',
  '7.0(3)I2(4)',
  '7.0(3)I2(3)',
  '7.0(3)I2(2y)',
  '7.0(3)I2(2x)',
  '7.0(3)I2(2w)',
  '7.0(3)I2(2v)',
  '7.0(3)I2(2s)',
  '7.0(3)I2(2r)',
  '7.0(3)I2(2e)',
  '7.0(3)I2(2d)',
  '7.0(3)I2(2c)',
  '7.0(3)I2(2b)',
  '7.0(3)I2(2a)',
  '7.0(3)I2(2)',
  '7.0(3)I2(1a)',
  '7.0(3)I2(1)',
  '7.0(3)I1(3b)',
  '7.0(3)I1(3a)',
  '7.0(3)I1(3)',
  '7.0(3)I1(2)',
  '7.0(3)I1(1z)',
  '7.0(3)I1(1b)',
  '7.0(3)I1(1a)',
  '7.0(3)I1(1)',
  '7.0(3)F3(5)',
  '7.0(3)F3(4)',
  '7.0(3)F3(3c)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(3)',
  '7.0(3)F3(2)',
  '7.0(3)F3(1)',
  '7.0(3)F2(2)',
  '7.0(3)F2(1)',
  '7.0(3)F1(1)',
  '7.0(2)N1(1)',
  '7.0(1)N1(1)',
  '7.0(0)N1(1)',
  '6.2(9c)',
  '6.2(9b)',
  '6.2(9a)',
  '6.2(9)',
  '6.2(8b)',
  '6.2(8a)',
  '6.2(8)',
  '6.2(7)',
  '6.2(6b)',
  '6.2(6a)',
  '6.2(6)',
  '6.2(5b)',
  '6.2(5a)',
  '6.2(5)',
  '6.2(31)',
  '6.2(3)',
  '6.2(2a)',
  '6.2(29)',
  '6.2(27)',
  '6.2(25)',
  '6.2(24a)',
  '6.2(24)',
  '6.2(23)',
  '6.2(22)',
  '6.2(21)',
  '6.2(20a)',
  '6.2(20)',
  '6.2(2)',
  '6.2(19)',
  '6.2(18)',
  '6.2(17a)',
  '6.2(17)',
  '6.2(16)',
  '6.2(15)',
  '6.2(14b)',
  '6.2(14a)',
  '6.2(14)',
  '6.2(13b)',
  '6.2(13a)',
  '6.2(13)',
  '6.2(12)',
  '6.2(11e)',
  '6.2(11d)',
  '6.2(11c)',
  '6.2(11b)',
  '6.2(11)',
  '6.2(10)',
  '6.2(1)',
  '6.1(2)I3(5b)',
  '6.1(2)I3(5a)',
  '6.1(2)I3(5)',
  '6.1(2)I3(4e)',
  '6.1(2)I3(4d)',
  '6.1(2)I3(4c)',
  '6.1(2)I3(4b)',
  '6.1(2)I3(4a)',
  '6.1(2)I3(4)',
  '6.1(2)I3(3a)',
  '6.1(2)I3(3)',
  '6.1(2)I3(2)',
  '6.1(2)I3(1)',
  '6.1(2)I2(3)',
  '6.1(2)I2(2b)',
  '6.1(2)I2(2a)',
  '6.1(2)I2(2)',
  '6.1(2)I2(1)',
  '6.1(2)I1(3)',
  '6.1(2)I1(2)',
  '6.0(2)U6(9)',
  '6.0(2)U6(8)',
  '6.0(2)U6(7)',
  '6.0(2)U6(6)',
  '6.0(2)U6(5c)',
  '6.0(2)U6(5b)',
  '6.0(2)U6(5a)',
  '6.0(2)U6(5)',
  '6.0(2)U6(4a)',
  '6.0(2)U6(4)',
  '6.0(2)U6(3a)',
  '6.0(2)U6(3)',
  '6.0(2)U6(2a)',
  '6.0(2)U6(2)',
  '6.0(2)U6(1a)',
  '6.0(2)U6(10a)',
  '6.0(2)U6(10)',
  '6.0(2)U6(1)',
  '6.0(2)U5(4)',
  '6.0(2)U5(3)',
  '6.0(2)U5(2)',
  '6.0(2)U5(1)',
  '6.0(2)U4(4)',
  '6.0(2)U4(3)',
  '6.0(2)U4(2)',
  '6.0(2)U4(1)',
  '6.0(2)U3(9)',
  '6.0(2)U3(8)',
  '6.0(2)U3(7)',
  '6.0(2)U3(6)',
  '6.0(2)U3(5)',
  '6.0(2)U3(4)',
  '6.0(2)U3(3)',
  '6.0(2)U3(2)',
  '6.0(2)U3(1)',
  '6.0(2)U2(6)',
  '6.0(2)U2(5)',
  '6.0(2)U2(4)',
  '6.0(2)U2(3)',
  '6.0(2)U2(2)',
  '6.0(2)U2(1)',
  '6.0(2)U1(4)',
  '6.0(2)U1(3)',
  '6.0(2)U1(2)',
  '6.0(2)U1(1a)',
  '6.0(2)U1(1)',
  '6.0(2)N2(7)',
  '6.0(2)N2(6)',
  '6.0(2)N2(5b)',
  '6.0(2)N2(5a)',
  '6.0(2)N2(5)',
  '6.0(2)N2(4)',
  '6.0(2)N2(3)',
  '6.0(2)N2(2)',
  '6.0(2)N2(1b)',
  '6.0(2)N2(1)',
  '6.0(2)N1(2a)',
  '6.0(2)N1(2)',
  '6.0(2)N1(1a)',
  '6.0(2)N1(1)',
  '6.0(2)A8(9)',
  '6.0(2)A8(8)',
  '6.0(2)A8(7b)',
  '6.0(2)A8(7a)',
  '6.0(2)A8(7)',
  '6.0(2)A8(6)',
  '6.0(2)A8(5)',
  '6.0(2)A8(4a)',
  '6.0(2)A8(4)',
  '6.0(2)A8(3)',
  '6.0(2)A8(2)',
  '6.0(2)A8(11b)',
  '6.0(2)A8(11a)',
  '6.0(2)A8(11)',
  '6.0(2)A8(10a)',
  '6.0(2)A8(10)',
  '6.0(2)A8(1)',
  '6.0(2)A7(2a)',
  '6.0(2)A7(2)',
  '6.0(2)A7(1a)',
  '6.0(2)A7(1)',
  '6.0(2)A6(8)',
  '6.0(2)A6(7)',
  '6.0(2)A6(6)',
  '6.0(2)A6(5b)',
  '6.0(2)A6(5a)',
  '6.0(2)A6(5)',
  '6.0(2)A6(4a)',
  '6.0(2)A6(4)',
  '6.0(2)A6(3a)',
  '6.0(2)A6(3)',
  '6.0(2)A6(2a)',
  '6.0(2)A6(2)',
  '6.0(2)A6(1a)',
  '6.0(2)A6(1)',
  '6.0(2)A4(6)',
  '6.0(2)A4(5)',
  '6.0(2)A4(4)',
  '6.0(2)A4(3)',
  '6.0(2)A4(2)',
  '6.0(2)A4(1)',
  '6.0(2)A3(4)',
  '6.0(2)A3(2)',
  '6.0(2)A3(1)',
  '6.0(2)A1(2d)',
  '6.0(2)A1(1f)',
  '6.0(2)A1(1e)',
  '6.0(2)A1(1d)',
  '6.0(2)A1(1c)',
  '6.0(2)A1(1b)',
  '6.0(2)A1(1a)',
  '6.0(2)A1(1)',
  '5.2(9a)',
  '5.2(9)',
  '5.2(8i)',
  '5.2(8h)',
  '5.2(8g)',
  '5.2(8f)',
  '5.2(8e)',
  '5.2(8d)',
  '5.2(8c)',
  '5.2(8b)',
  '5.2(8a)',
  '5.2(8)',
  '5.2(7)',
  '5.2(6b)',
  '5.2(6a)',
  '5.2(6)',
  '5.2(5)',
  '5.2(4)',
  '5.2(3a)',
  '5.2(3)',
  '5.2(2s)',
  '5.2(2d)',
  '5.2(2a)',
  '5.2(2)',
  '5.2(1)N1(9b)',
  '5.2(1)N1(9a)',
  '5.2(1)N1(9)',
  '5.2(1)N1(8b)',
  '5.2(1)N1(8a)',
  '5.2(1)N1(8)',
  '5.2(1)N1(7)',
  '5.2(1)N1(6)',
  '5.2(1)N1(5)',
  '5.2(1)N1(4)',
  '5.2(1)N1(3)',
  '5.2(1)N1(2a)',
  '5.2(1)N1(2)',
  '5.2(1)N1(1b)',
  '5.2(1)N1(1a)',
  '5.2(1)N1(1)',
  '5.2(1)',
  '5.0(8a)',
  '5.0(8)',
  '5.0(7)',
  '5.0(4d)',
  '5.0(4c)',
  '5.0(4b)',
  '5.0(4)',
  '5.0(3)U5(1j)',
  '5.0(3)U5(1i)',
  '5.0(3)U5(1h)',
  '5.0(3)U5(1g)',
  '5.0(3)U5(1f)',
  '5.0(3)U5(1e)',
  '5.0(3)U5(1d)',
  '5.0(3)U5(1c)',
  '5.0(3)U5(1b)',
  '5.0(3)U5(1a)',
  '5.0(3)U5(1)',
  '5.0(3)U4(1)',
  '5.0(3)U3(2b)',
  '5.0(3)U3(2a)',
  '5.0(3)U3(2)',
  '5.0(3)U3(1)',
  '5.0(3)U2(2d)',
  '5.0(3)U2(2c)',
  '5.0(3)U2(2b)',
  '5.0(3)U2(2a)',
  '5.0(3)U2(2)',
  '5.0(3)U2(1)',
  '5.0(3)U1(2a)',
  '5.0(3)U1(2)',
  '5.0(3)U1(1d)',
  '5.0(3)U1(1c)',
  '5.0(3)U1(1b)',
  '5.0(3)U1(1a)',
  '5.0(3)U1(1)',
  '5.0(3)A1(2a)',
  '5.0(3)A1(2)',
  '5.0(3)A1(1)',
  '5.0(1b)',
  '5.0(1a)'
);

workarounds = make_list(CISCO_WORKAROUNDS['cfs_enabled']);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , cbi,
  'cmds'     , ['show running-status']
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  workarounds:workarounds,
  vuln_versions:version_list
);