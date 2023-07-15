#TRUSTED 9b894385ce44790e2ab560ff51630baca8194781be5ea80d93ddad75ce41b4f969186220016b8207c73477094eb7662d9f68f9bcab44b7df077d42b9176c9976e0fc620f98dc6b1994e05bcf8922774ab13100331fca4a5e310ff7a472a5942dbc34e28a45e8b8a27add2bb6cbb9de0aa4245b4cacac1d37709c40b77b0cba6273e7c7d0cd08b8c42a827981005d4602ad261c7cb054d1591f6f6ea2e880a2cde45896b17a3faee8414e5418b5feb89f83b20aa87877ccd2c12e343d56eb8101594e2c3fa7e45688be97d78900abb1bec942c32730a84ab66d4eb5ec4e03049243b67003162f7a6b1375d873cb27612772745f32d50e10d328e6c3943b935f9faf601d859fb94935e5b571034f245f0a7f3ae67c92d298797105cae922e4e22f91bd2fca4f3ad50a13a6137150efbb2fa09f4c32539e81d40eeed16275400a9a0076b810b5be4f9ea228fffb7b7abfd9d442120bee15fff6235ea777c68c9a617186c85c73deb429cc5effdad4083a033d844ab2feb0e70af36e25e0d88f9f745aa916c50793c2e6278233865409a42a7766cbfed7f03e78498576b0e27ca47052f17843c1b4e61a8d5f6be9e6ae5749486ea36905d63f231444b8a69dfccd49023d083eb79f9a15e5d1324d74709e9f2d1bea3a9e16b03045e643edf45324b998d0a0dc13c2af0d605f1d6a3319b3601e39df97eea6b01da88b5940f5a13023
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131698);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/25");

  script_cve_id("CVE-2019-1795");
  script_bugtraq_id(108479);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh20029");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh20359");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh66202");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh66214");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh66219");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh66243");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh66257");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh66259");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk30761");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-nxos-cmdinj-1795");

  script_name(english:"Cisco NX-OS Software Command Injection (cisco-sa-20190515-nxos-cmdinj-1795)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a command injection vulnerability due to
insufficient validation of arguments passed to a specific CLI command on an affected device. An authenticated, local
attacker can exploit this to execute arbitrary commands on the underlying Linux operating system with root privileges.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-nxos-cmdinj-1795
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d9ac45f1");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh20029");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh20359");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh66202");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh66214");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh66219");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh66243");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh66257");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh66259");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk30761");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvh20029, CSCvh20359, CSCvh66202, CSCvh66214,
CSCvh66219, CSCvh66243, CSCvh66257, CSCvh66259, and CSCvk30761");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1795");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/04");

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
    cbi = 'CSCvh20359';
  else if (product_info.model =~ '^(30|90)[0-9]{2}')
    cbi = 'CSCvh20029';
  else if (product_info.model =~ '^35[0-9]{2}')
    cbi = 'CSCvh66219';
  else if (product_info.model =~ '^36[0-9]{2}' || product_info.model =~ '^95[0-9]{2}R')
    cbi = 'CSCvh66202';
  else if (product_info.model =~ '^(55|56|60)[0-9]{2}')
    cbi = 'CSCvh66214';
  # Combining these two BIDs even though they're broken out in advisory as it's unclear whether we can tell Hyper-V
  # and vSphere apart
  else if (product_info.model =~ '^10[0-9]{2}V')
    cbi = 'CSCvk30761, CSCvh66257';
}
else if ('MDS' >< product_info.device && product_info.model =~ '^90[0-9]{2}')
  cbi = 'CSCvh20359';
else if ('UCS' >< product_info.device && product_info.model =~ '^6[23][0-9]{2}')
  cbi = 'CSCvh66243';

if (cbi == '')
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
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
  '5.2(1)SV3(1.3a)',
  '5.2(1)SV3(1.3b)',
  '5.2(1)SV3(1.3c)',
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
  '6.2(20a)',
  '7.0(3)F3(1)',
  '7.0(3)F3(2)',
  '7.0(3)F3(3)',
  '7.0(3)I4(1)',
  '7.0(3)I4(2)',
  '7.0(3)I4(3)',
  '7.0(3)I4(4)',
  '7.0(3)I4(5)',
  '7.0(3)I4(6)',
  '7.0(3)I4(7)',
  '7.0(3)I7(5a)',
  '7.0(3)I7(1)',
  '7.0(3)I7(2)',
  '7.3(2)D1(1A)',
  '7.3(2)D1(1)',
  '7.3(2)D1(2)',
  '8.2(1)',
  '8.2(2)'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info.version,
  'bug_id'   , cbi
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params
);
