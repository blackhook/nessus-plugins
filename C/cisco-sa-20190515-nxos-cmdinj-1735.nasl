#TRUSTED 804e017205fb20bfde49ec62fb618847188a9410f89d25e5e8a7328aa178108000648cbfcb78dfc8882d666c4280899eb8766ecd70be47fa539b12ab92be01a6b04034ee8f30f847425a3a8ca5f18cc502bd214b0f9037733d6d2e5ec3dc394558f18960d2b4ba145e0ba2717fa2bc9d627d49e2be80b795575720c7c61ee72e2fd1a0c268adaecb2080aa3ba12b7cf606f2cf3997fc639acdc70345f570a3458a7805702e742a120cd394b3a11ec837bcb8147017f57c999a7bf3d166cf4ceb0101994267095449c7a6803950ec121402f0e596dd798552486373b1df7c6fed9bf2618be8f7a66b7fbb6c2a63533ec8e239b900e9f4f237aa2220a21d9d4609084ea8da99609cb1f49ccc4ee2b0dee64d19b9c8c38197f5a21d503f0ab81e24e6c3742245ee539e80d3919e9f0e2cac7d030424e2ce5205feea6c9e6982f21e2d7fa2012dc4d0c3bea15459357c5640e83f458dd5f5d6cc85eedeeaa347ac3962a27c5bdbbf9502205769f2e34559493d1cd02255414f1785baddbac86f3f232c0fbf668b9a06f04c5424cc6c767bd0235b6659b28775b4cb2ab15d8651227434f708cc460a6e57e459b6852921369c03619e7396f169a5adef5db9a27896f7a7521d22e8ea75f690c3399f72eef6d48d95a67fb779268e16e80d839c71f63c9285b033d20cd4b7d15e5a009b93b0540275a373fb5b445164ec393d83cd3b92
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130917);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/25");

  script_cve_id("CVE-2019-1735");
  script_bugtraq_id(108365);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj63728");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj63877");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk52969");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk52971");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk52972");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk52975");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk52985");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk52988");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-nxos-cmdinj-1735");

  script_name(english:"Cisco NX-OS Software Command Injection (cisco-sa-20190515-nxos-cmdinj-1735)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a command injection vulnerability due to
insufficient validation of arguments passed to certain CLI commands on an affected device. An authenticated, local
attacker can exploit this to execute arbitrary commands on the underlying operating system with elevated privileges.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-nxos-cmdinj-1735
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2afe9738");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj63728");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj63877");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk52969");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk52971");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk52972");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk52975");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk52985");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk52988");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvj63728, CSCvj63877, CSCvk52969, CSCvk52971,
CSCvk52972, CSCvk52975, CSCvk52985, and CSCvk52988.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1735");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

cbi = '';
if ('Nexus' >< product_info.device)
{
  if (product_info.model =~ '^7[07][0-9]{2}')
    cbi = 'CSCvj63728';
  else if (product_info.model =~ '^(30|35|90)[0-9]{2}')
    cbi = 'CSCvj63877, CSCvk52971';
  else if (product_info.model =~ '^36[0-9]{2}' || product_info.model =~ '^95[0-9]{2}R')
    cbi = 'CSCvk52988';
  else if (product_info.model =~ '^(55|56|60)[0-9]{2}')
    cbi = 'CSCvk52972';
  # None of the BIDs mention 1000VE, grouping it here as it seems closest
  else if (product_info.model =~ '^10[0-9]{2}V(E)?')
    cbi = 'CSCvk52969, CSCvk52985';
}
else if ('MDS' >< product_info.device && product_info.model =~ '^90[0-9]{2}')
  cbi = 'CSCvj63728';
else if ('UCS' >< product_info.device && product_info.model =~ '^6[234][0-9]{2}')
  cbi = 'CSCvk52975';

if (cbi == '')
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
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
  '6.0(2)A8(10a)',
  '6.0(2)A8(10)',
  '7.0(3)',
  '7.0(0)N1(1)',
  '7.0(1)N1(1)',
  '7.0(1)N1(3)',
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
  '7.0(3)F3(3c)',
  '7.0(3)F3(3b)',
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
  '7.0(3)I7(5a)',
  '7.0(3)I5(1)',
  '7.0(3)I5(2)',
  '7.0(3)I6(1)',
  '7.0(3)I6(2)',
  '7.0(3)I7(1)',
  '7.0(3)I7(2)',
  '7.0(3)I7(3)',
  '7.0(3)I7(4)',
  '7.0(3)I7(5)',
  '7.0(3)I7(5a)',
  '7.3(0.2)',
  '7.3(0)D1(1)',
  '7.3(0)DX(1)',
  '7.3(0)DY(1)',
  '7.3(0)N1(1)',
  '7.3(0)N1(1b)',
  '7.3(0)N1(1a)',
  '7.3(1)D1(1B)',
  '7.3(1)D1(1)',
  '7.3(1)DY(1)',
  '7.3(1)N1(0.1)',
  '7.3(1)N1(1)',
  '7.3(2)D1(1A)',
  '7.3(2)D1(1)',
  '7.3(2)D1(2)',
  '7.3(2)D1(3)',
  '7.3(2)D1(3a)',
  '7.3(2)N1(0.296)',
  '7.3(2)N1(1)'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info.version,
  'bug_id'   , cbi,
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
