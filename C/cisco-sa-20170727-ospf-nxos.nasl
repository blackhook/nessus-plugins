#TRUSTED 9e928d34e2655a44cdc2d042bcc8f06cbe62043521134274a471b8408e894105d104dcdd84bcd270b9acdc23356795f4b174c6c6e496896c1e266e471aa72f12ca0f9eb0ea46c228c2f5e4694a70befc1a6c608406702b2eafd7a068a7891a0b403ce5e432095b8dc378d144114a03d5eb714d78ffa1d3f8a3baad25e3cc6188e52c882951742426e5488d19c96e77825786b2a38a3218b85d96ea4aac0716a39143ea7a73c8e49abd3b1b71942e3de797e5c5c95a173352865d0995e25d1ab59edb6c3ddf49c4dfef20c8df77a72938bd48f5dbe267f27217318e94cac9ca78412445bfa876aefa834811c2156391363a3a8e5b4d9aa17044ebd8b326e2fb9b780ce8c3ccb8d042641a948007e1e57cfd166a2f6fc59af198b159846a5d3a244b8abe875b67eca76cbf28d9671200247fb13cb161ef0a52eb646587b9d2526c9c9dd69a0a2b993830ec8bdc7161f012a64c352986daf964172edb3ad4381150221b4a9a99ffa88758ffe3175c5c5407ecad58b3eafcfc27461b2dccdbd9ae5b1b5acfe73e4eec53b3ab05d180f51828ef01ba2b6dec4e1bf7e1acc52168b87d7ab5fd1e7418a3a5654f360a4eabbd1cca56549a3312cb499cf7dbb121791236fe1a62adbb6c3d72a7ff5de1fad8e82e9bb29348673046402bb51fd36f586e8ea6754e35b1b03c0de44d5a5c54aeb089dd1f4be4d04516d33abd443139b84de9
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131396);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/24");

  script_cve_id("CVE-2017-6770");
  script_bugtraq_id(100005);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf28683");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve47401");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170727-ospf");

  script_name(english:"Cisco NX-OS Software OSPF LSA Manipulation (cisco-sa-20170727-ospf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a vulnerability involving the Open Shortest
Path First (OSPF) Routing Protocol Link State Advertisement (LSA) database. An unauthenticated, remote attacker can
exploit this, by injecting crafted OSPF LSA type 1 packets, to cause the targeted router to flush its routing table and
propagate the crafted OSPF LSA type 1 update through the OSPF AS domain, allowing the attacker to intercept or
black-hole traffic. Successful exploitation of this vulnerability requires that an attacker first accurately determine
certain parameters within the LSA database on the target router.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170727-ospf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c4d1c57");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve47401");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf28683");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvf28683 and CSCve47401.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6770");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

version_list = make_list(
  '4.1(2)',
  '4.1(3)',
  '4.1(4)',
  '4.1(5)',
  '5.0(2a)',
  '5.0(3)',
  '5.0(5)',
  '4.2(2a)',
  '4.2(3)',
  '4.2(4)',
  '4.2(6)',
  '4.2(8)',
  '5.1(1)',
  '5.1(1a)',
  '5.1(3)',
  '5.1(4)',
  '5.1(5)',
  '5.1(6)',
  '5.2(1)',
  '5.2(3a)',
  '5.2(4)',
  '5.2(5)',
  '5.2(7)',
  '5.2(9)',
  '6.1(1)',
  '6.1(2)',
  '6.1(3)',
  '6.1(4)',
  '6.1(4a)',
  '6.1(5)',
  '6.1(3)S5',
  '6.1(3)S6',
  '4.0(0)N1(1a)',
  '4.0(0)N1(2)',
  '4.0(0)N1(2a)',
  '4.0(1a)N1(1)',
  '4.0(1a)N1(1a)',
  '4.0(1a)N2(1)',
  '4.0(1a)N2(1a)',
  '4.1(3)N1(1)',
  '4.1(3)N1(1a)',
  '4.1(3)N2(1)',
  '4.1(3)N2(1a)',
  '4.2(1)N1(1)',
  '4.2(1)N2(1)',
  '4.2(1)N2(1a)',
  '5.0(2)N1(1)',
  '5.0(2)N2(1)',
  '5.0(2)N2(1a)',
  '5.0(3)N1(1c)',
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
  '5.2(9)N1(1)',
  '6.0(1)',
  '6.0(2)',
  '6.0(3)',
  '6.0(4)',
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
  '6.0(2)U4(1)',
  '6.0(2)U4(2)',
  '6.0(2)U4(3)',
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
  '6.2(2)',
  '6.2(2a)',
  '6.2(6)',
  '6.2(6b)',
  '6.2(8)',
  '6.2(8a)',
  '6.2(8b)',
  '6.2(10)',
  '6.2(12)',
  '7.0(3)',
  '7.0(0)N1(1)',
  '7.0(1)N1(1)',
  '7.0(1)N1(3)',
  '7.0(2)N1(1)',
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
  '7.0(3)I3(1)',
  '7.0(3)I4(1)',
  '7.0(3)I4(2)',
  '7.0(3)I4(3)',
  '7.0(3)N1(1)',
  '7.0(4)N1(1)',
  '7.0(5)N1(1)',
  '7.0(5)N1(1a)',
  '7.0(6)N1(1)',
  '7.0(7)N1(1)',
  '7.0(8)N1(1)',
  '7.1(0)N1(1a)',
  '7.1(0)N1(1b)',
  '7.1(1)N1(1)',
  '7.1(2)N1(1)',
  '7.1(3)N1(1)',
  '7.1(3)N1(2)',
  '7.1(3)N1(2.1)',
  '7.1(3)N1(3.12)',
  '7.1(4)N1(1)',
  '7.2(0)D1(0.437)',
  '7.2(0)N1(1)',
  '7.2(0)ZZ(99.1)',
  '7.2(1)D1(1)',
  '7.2(1)N1(1)',
  '7.3(0.2)',
  '7.3(0)N1(1)',
  '7.3(1)N1(0.1)',
  '7.3(1)N1(1)',
  '7.3(2)N1(0.296)',
  '8.0(1)S2',
  '8.0(1)',
  '8.1(1)'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['ios_iosxe_nxos_ospf'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCve47401, CSCvf28683',
  'cmds'     , make_list('show ip ospf interface')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
