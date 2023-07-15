#TRUSTED 376227b1149da1d356a77654b7ff20695cfe86b73bdc83f621d2229810f7ed9c3a271b4e8b486a71fea64845aa72bbe7a2cb47a3c8579c6e784782346971d57eac8c5e0278b5bb36972b50ed5e254949bbe16a86f242034ccab410acdd1f533bd1548a2eb72925b83e86a9a495a7e63a6a69435f76600a1fac8892c3cd8fc3a037528522628bc495afff6a7ba68cf291542f79124c03641ea484e6381ba87575525d8bc203d49a7caef7648981c08538eb2e5d42356648452ea1c5db2cbcea26dda7f2d17559155f8129935cece7238c8a8739bd1cf6041a30d0627161721a3bfd0b3c5e1b10e73c1d0aed62a172a2073218309404feffd5a87b9c0941a287e0721755562240506e0bfe8c6b0c76c89584c606281d8e1cdc0575b91fe8d5dacc2af8a98bbd5631c66b77bebd41de3219f41f6485018dfc0b869e1c914ba8a40ad2d99a74174206f3a3437aa7dc45a9f2423c2dc37fc200b9e8c379f8bdf3d850eeb51b7996a61878a1520588002ec731ae87c69eb07564cd5d791915a9e4566abe51951db20db49328f3270cfac1d24a12cb4991f1183ce5457a741893cfd50bd2576b3e29c9ead658a44cf78ad557549cf0cfb028c42f3b1b04568801814b5f120d3a329ba0e2737911dd5ba0b71792555f2e017dcba5f5073badb9981e2ca7676f789a21868dff70169710140c839bc36b132d75c981f843cfff47cf0d2dbe
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138439);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/15");

  script_cve_id("CVE-2018-0294");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd13993");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd34845");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd34857");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd34862");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd34879");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-nxosadmin");

  script_name(english:"Cisco NX-OS Software Unauthorized Administrator Account (cisco-sa-20180620-nxosadmin)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-20180620-nxosadmin)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, a improper file handling vulnerability exists in Cisco NX-OS Software. 
Therefore, an authenticated, local attacker can exploit this via CLI commands to create a unathorized account 
with administrator privilages that does not require a password for authentication and will not show up in audit 
logs or records.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-nxosadmin
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f6cae479");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-67770");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-67770");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd13993");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd34845");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd34857");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd34862");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd34879");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the Cisco bug ID");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0294");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/14");

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

if ('Nexus' >< product_info.device) 
{
  if (product_info.model =~ '^(20|55|56|60)[0-9][0-9]')
  {
    cbi = 'CSCvd13993';
    version_list = [
      {'min_ver' : '0.0', 'fix_ver' : '7.1(5)N1(1)'},
      {'min_ver' : '7.2', 'fix_ver' : '7.3(2)N1(1)'}
    ];
  }
  else if (product_info.model =~ '^35[0-9][0-9]')
  {
    cbi = 'CSCvd34857';
    version_list = [
      {'min_ver' : '6.0(2)', 'fix_ver' : '6.0(2)A8(7)'},
      {'min_ver' : '7.0(3)', 'fix_ver' : '7.0(3)I7(2)'}
    ];
  }
  else if (product_info.model =~ '^40[0-9][0-9]')
  {
    cbi = 'CSCvd34879';
    version_list = [
      {'min_ver' : '4.1', 'fix_ver' : '4.1(2)E1(1s)'}
    ];
  }
  else if (product_info.model =~ '^1[10][0-9][0-9]')
  {
    cbi = 'CSCvd34845';
    version_list = [
      {'min_ver' : '0.0', 'fix_ver' : '5.2(1)SV3(3.1)'}
    ];
  }
}
else if ('UCS' >< product_info.device && product_info.model =~ "^6[123][0-9][0-9]")
{
  cbi = 'CSCve02461';
  version_list = [
    {'min_ver' : '0.0', 'fix_ver' : '3.1(3a)'},
    {'min_ver' : '3.2', 'fix_ver' : '3.2(1d)'}
  ];
}

if (cbi == '')
  audit(AUDIT_HOST_NOT, 'affected');

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , cbi
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:version_list
);
