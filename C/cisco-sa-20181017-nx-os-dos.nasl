#TRUSTED 6f0fa9c08155880821d65f3daf3792e4370889c0cb3a0b45ec084272fc591395acd27fb28ab78c7ae8f78f24422b0bc014c010131f752f279263ca7bc1b414e81edacd189561de10571f432406285b248c202e4696be4a8919b7e8876b33fc9cd7338418a3c40fc983b1d9683ebe61c84f2ec31514ebaa48945c1c5d7c9de782144cd43aaed49c3040fed664d13a128350f29d41b88951ad0c208aa12b04655bdda64945c0224ccf8cc6d66e3dd2dd93d971d7fa53f8f072940a0e010db67415a2d3ddc1a9f17f909cee9a3d58bd563e360049c9d8b543673730768ba138e12c5b275fde2084bd672fa5d01d40dc6bf0f6031ccd5f7753d7d07c4975caf079a4070e7dc8cddfa0bf26fb0b66c4e7983147870d6eab0bcdcb11054a9b85fb86a234e91cfdb6cf1fa7216423162dda24bd0a87ae6913d3f5e5f3c2cf42bdeebc5e41a7fdf876800a0f8104e701b3a3dfb062286d352decad0cd4485603a829099c0ca18c795f0b050ff875a2d9295043024c7bb6279f4154b476dcfdcf15ede1666b7f25627966e00fb3e0c250eeea7702efa95b68f82c9adf39c820e9ceabee85dd6e2df3ab48cc7044cd053cc4becca58acd5040fa946c499a826d3a46d26f185e7456558fa516c341c2354792d398da9ee7d3edbc114a5e15c51e72314cca6398e174d4d898dabf70f83d2018d96762f8ff16719424c9cea91e819826a03dc5
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134947);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/19");

  script_cve_id("CVE-2018-0395");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuc98542");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj94174");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj96148");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20181017-fxnx-os-dos");

  script_name(english:"Cisco NX-OS Software Link Layer Discovery Protocol Denial of Service Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in Cisco NX-OS Software due to improper input validation of
certain type, length, value (TLV) fields of the LLDP frame header. An unauthenticated, local attacker can exploit this
issue, by sending a crafted LLDP packet to an interface on the targeted device, to cause the system to reload.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181017-fxnx-os-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3775192a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuc98542");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj94174");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj96148");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCuc98542, CSCvj94174, CSCvj96148");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0395");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model", "Settings/ParanoidReport");

  exit(0);
}


include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:"Cisco NX-OS Software");

if ('Nexus' >< product_info['device'])
{
  # check if 2000 , 5500, 5600, or 6000 series
  if (preg(pattern:"^20[0-9]{2}$", string:product_info['model']) ||
      preg(pattern:"^5[5-6][0-9]{2}$", string:product_info['model']) ||
      preg(pattern:"^6[0-9]{3}$", string:product_info['model']))
    {
    bid = 'CSCuc98542';
    vuln_ranges = [
    {'min_ver' : '5.0', 'fix_ver' : '7.0(0)N1(1)'}
    ];
  }
  # check if 3000 series
  else if (preg(pattern:"^30[0-9]{2}$", string:product_info['model']))
  {
    bid = 'CSCuc98542';
    vuln_ranges = [
    {'min_ver' : '5.0(3)', 'fix_ver' : '6.0(2)U1(2)'}
    ];
  }
  # check if 3500 series
  else if (preg(pattern:"^35[0-9]{2}$", string:product_info['model']))
  {
    bid = 'CSCuc98542';
    vuln_ranges = [
    {'min_ver' : '5.0(3)', 'fix_ver' : '6.0(2)A1(1b)'}
    ];
  }
  # check if 7000 or 7700 series
  else if (preg(pattern:"^7(0|7)[0-9]{2}$", string:product_info['model']))
  {
    bid = 'CSCuc98542';
    vuln_ranges = [
    {'min_ver' : '5.2', 'fix_ver' : '5.2(9)'},
    {'min_ver' : '6.1', 'fix_ver' : '6.1(3)'}
    ];
  }
  # check if 9000 series
  else if (preg(pattern:"^90[0-9]{2}$", string:product_info['model']))
  {
    bid = 'CSCvj94174';
    vuln_ranges = [
    {'min_ver' : '0.0', 'fix_ver' : '13.2(2l)'}
    ];
  }
}
else if ('MDS' >< product_info['device'])
{
  # check if 9000 series
  if (preg(pattern:"^90[0-9]{2}$", string:product_info['model']))
  {
    bid = 'CSCuc98542';
    vuln_ranges = [
    {'min_ver' : '5.2', 'fix_ver' : '6.2(1)'}
    ];
  }
}
else if ('UCS' >< product_info['device'])
{
  # check if 6100, 6200, and 6300 Series
  if (preg(pattern:"^6[1-3][0-9]{2}$", string:product_info['model']))
    {
    bid = 'CSCvj96148';
    vuln_ranges = [
    {'min_ver' : '0.0', 'fix_ver' : '2.2(8l)'},
    {'min_ver' : '3.1', 'fix_ver' : '3.1(3j)'},
    {'min_ver' : '3.2', 'fix_ver' : '3.2(3g)'},
    {'min_ver' : '4.0', 'fix_ver' : '4.0(1a)'}
    ];
  }
}
if (bid == '')
{
  audit(AUDIT_HOST_NOT, 'a vulnerable model');
}


if (report_paranoia < 2) audit(AUDIT_PARANOID);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = [];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'bug_id'   , bid,
  'version'  , product_info['version']
);

cisco::check_and_report(product_info:product_info,
  workarounds       : workarounds,
  workaround_params : workaround_params,
  reporting         : reporting,
  vuln_ranges       : vuln_ranges
);
