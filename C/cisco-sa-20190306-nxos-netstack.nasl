#TRUSTED 819a11cde8a9096ca3c21684f3d3eec4420fc29d0054015944183bc60e81858a9917bce4dca36d8646250bb426f58bcbbd80393fd6022a1298dd2ec49ba79921b1461621f3447ed414e306f42f9e839ed8d2f2f6bb418179c9ea93b6526071ad89cf7db3d07dcbce856b2861c4c15fadd88c33ee2f7dbf2be3adbb94af6050bf2925543d265486692d132f2c468421fcdac5b4e74e0b4e1c37e6072bef7c655394b0d641fdba98e5c225929acbc82d91386d99df941129b9469b948c6fcb59d1e2709a006df2bd49fdd900b548dbbddfadbf45e8359e51359e1d4b500f2a6d6680f3d152bd93d588f4db7c21d3b33ca3cea9dd92174931fe1d3b37298f6d8699c8c7bf21efd6ea08c249848b1fc8ac6df088ed6b0337817ad1a35aaee92dd308bc14dbe74fcaa933848b141785ccbb0a5fa14e00def7bbabe2eb7e16e2661072e70e58efbeedff5f9a2a884bbc8dbf0111f248e654dc7b8e3d05c99c4f77b46e63cb4aa9219621802b2663c83e56431dca2474b81c4e36a37c898c7299fcbbb3bc79adfce958444b78a070a41f38d05bc629a3ab743e769a82d384ded2adc5231199fe747dd86575ee8a8986db752c51b5badb5154f2cb050c54d360bb0ef3e4c49d1a66e2be5193ae7bf7ede7b059f8351159894170e061a89f234743e8e16d2246c0d362a8630ef9fb11c1dbacff5df59dd94830f2c4b25bdc2b05e9eed9fc
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134948);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/31");

  script_cve_id("CVE-2019-1599");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk55013");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm53108");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm53112");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm53113");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm53114");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm53115");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm53116");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm53125");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm53128");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20181017-fxnx-os-dos");

  script_name(english:"Cisco NX-OS Software Netstack DoS (cisco-sa-20190306-nxos-netstack)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in Cisco NX-OS Software due to allocating and freeing memory buffers in
the network stack. An unauthenticated, remote attacker can exploit this issue by sending crafted TCP streams to an affected
device in a sustained way. If the attacker is succesful then this will result in the network stack running out of available
buffers, thus impairing operations of the control plane and management plane protocols.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190306-nxos-netstack
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?afa8810a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk55013");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm53108");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm53112");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm53113");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm53114");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm53115");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm53116");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm53125");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm53128");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvi92332");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1599");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');
model = toupper(product_info['model']);
device = toupper(product_info['device']);
version = toupper(product_info['version']);

if ('UCS' >< device) {
  if (model =~ "^(62|63)[0-9]{2}$") {
    bug_id = 'CSCvm53116';
    vuln_ranges = [
      {'min_ver' : '0.0', 'fix_ver' : '3.2(3j)'},
      {'min_ver' : '4.0', 'fix_ver' : '4.0(2a)'}
    ];
  }
  else if (model =~ "^64[0-9]{2}$") {
    bug_id = 'CSCvm53125';
    vuln_ranges = [
      {'min_ver' : '4.0', 'fix_ver' : '4.0(2a)'}
    ];
  }
}
else if ('NEXUS' >< device) {
  # check if 1000v for Hyper-V
  if ("1000V" >< model && "SM" >< version) {
    bug_id = 'CSCvm53112';
    vuln_ranges = [
    {'min_ver' : '0.0', 'fix_ver' : '5.2(1)SM3(2.1)'}
    ];
  }
  # check if 1000v for VMWare
  else if ("1000V" >< model && "SV" >< version) {
    bug_id = 'CSCvm53113';
    vuln_ranges = [
      {'min_ver' : '0.0', 'fix_ver' : '5.2(1)SV3(4.1a)'}
    ];
  }
  # check if 3000 series
  else if (model =~ "^30[0-9]{2}$") {
    bug_id = 'CSCvk55013';
    vuln_ranges = [
      {'min_ver' : '0.0', 'fix_ver' : '7.0(3)I4(9)'},
      {'min_ver' : '9.2', 'fix_ver' : '9.2(2)'}
    ];
  }
  # check if 3500 series
  else if (model =~ "^35[0-9]{2}$") {
    bug_id = 'CSCvm53114';
    vuln_ranges = [
      {'min_ver' : '0.0', 'fix_ver' : '6.0(2)A8(11)'},
      {'min_ver' : '7.0(3)', 'fix_ver' : '7.0(3)I7(6)'},
      {'min_ver' : '9.2', 'fix_ver' : '9.2(2)'}
    ];
  }
  # check if 3600 series
  else if (model =~ "^36[0-9]{2}$") {
    bug_id = 'CSCvm53108';
    vuln_ranges = [
      {'min_ver' : '7.0(3)', 'fix_ver' : '7.0(3)F3(5)'},
      {'min_ver' : '9.2', 'fix_ver' : '9.2(2)'}
    ];
  }
  # check if 5500, 5600, or 6000 series
  else if (model =~ "^5[5-6][0-9]{2}$" ||
  model =~ "6[0-9]{2}") {
    bug_id = 'CSCvm53115';
    vuln_ranges = [
      {'min_ver' : '0.0', 'fix_ver' : '7.1(5)N1(1b)'},
      {'min_ver' : '7.2', 'fix_ver' : '7.3(5)N1(1)'}
    ];
  }
  # check if 7000 or 7700 series
  else if (model =~ "^7(0|7)[0-9]{2}$") {
    bug_id = 'CSCvm53128';
    vuln_ranges = [
      {'min_ver' : '0.0', 'fix_ver' : '6.2(22)'},
      {'min_ver' : '7.2', 'fix_ver' : '7.3(3)D1(1)'},
      {'min_ver' : '8.0', 'fix_ver' : '8.2(3)'},
      {'min_ver' : '8.3', 'fix_ver' : '8.3(2)'}
    ];
  }
  # check if 9000 series
  else if (model =~ "^90[0-9]{2}$") {
    bug_id = 'CSCvk55013';
    vuln_ranges = [
      {'min_ver' : '0.0', 'fix_ver' : '7.0(3)I4(9)'},
      {'min_ver' : '7.0(3)I5', 'fix_ver' : '7.0(3)I7(6)'},
      {'min_ver' : '9.2', 'fix_ver' : '9.2(2)'}
    ];
  }
  # check if 9500 R-Series
  else if (model =~ "^95[0-9]{2} R$") {
    bug_id = 'CSCvm53108';
    vuln_ranges = [
      {'min_ver' : '7.0(3)', 'fix_ver' : '7.0(3)F3(5)'},
      {'min_ver' : '9.2', 'fix_ver' : '9.2(2)'}
    ];
  }
}
if (bug_id == '') {
  audit(AUDIT_HOST_NOT, 'an affected model');
}

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = [];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , bug_id,
  'version'  , product_info['version']
);

cisco::check_and_report(
  product_info:product_info,
  workarounds       : workarounds,
  workaround_params : workaround_params,
  reporting         : reporting,
  vuln_ranges       : vuln_ranges
);
