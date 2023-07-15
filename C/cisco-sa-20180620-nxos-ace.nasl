#TRUSTED 86434e0b496d8689e80b2361d0a12d71b0ddfdc17b75630101b3eb1e2e5576c8bb36eb7df2d6aadffc2e4443ccec0b7581205ecc06ae4230446cc3d116de5c60c97d38d0cf5cd0fe805b2f431f2e21f35f02fbba493eabd5a5eb8dbab913cb4db47323b89f15c89044bc23b791f9fac8a474b0b8dc5ea910a2a1e7869e84161a5575449cdb5ea411a5af698008791066aba3fd22e840760dc1535a935f92ed83090b6cc1dc4788322d1c7cdee6419385369039e7735094ccaec784977a1976d4ccff546dbdda4bd28f8f4601ded4edbd468252bc183f07ddeab1626316a87a1dff04c3810747241631f8e567244249163df23ade63473edf20384c8c293dcd8662f46f5fb92048c2ffaff5be3679a402c45054292756dc41a36fabab9f0e3eb0f8951531493c85960889b3901d0dcc3cfdc0f65b28d33fc487c9e274e3d64e045ac61e56cf78cea6581947d2dd3784aaee12ab3d71d93021fbb51c7d7fdbcd4067597dfbeb6e1636bcb1c4884b16970f7f592686ebb02ed311d1e5a832f8232cf534959109ca4431f9266d43ab47966acde464d7f5dfb3377e11d460d6e8d560fb624ea4b79fe106d5ab75d844b66eff88bad7cb48184e6815fc2db93a0d9191aeb00fb92fbeac51c30ee6d6ef09c5e12877f43dd4ca47326aa0bda53ed41c45533a009e6c2758c8d4933a43208c8258359cc7fb0ec0b67846c418681cadeda9
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138438);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/19");

  script_cve_id("CVE-2018-0304");
  script_bugtraq_id(104513);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd69951");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02459");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02461");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02463");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02474");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-fxnxos-ace");

  script_name(english:"Cisco NX-OS Software Cisco Fabric Services Arbitrary Code Execution (cisco-sa-20180620-fxnxos-ace)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A arbitrary code execution vulnerability exists in Cisco Fabric Services NXOS software 
due to insufficient validation of packet headers. An unauthenticated, remote attacker can
exploit this, via crafted packets, to execute arbitrary code. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-67770");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-fxnxos-ace
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?267dc032");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd69951");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02459");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02461");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02463");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02474");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvd69951, CSCve02459, CSCve02461, CSCve02463,
CSCve02474, CSCve04859");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0304");

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

product_info = cisco::get_product_info(name:"Cisco NX-OS Software");

cbi = '';
version_list=make_list('');

if ('MDS' >< product_info.device && product_info.model =~ "^90[0-9][0-9]")
{
  cbi = 'CSCvd69951';
  version_list = [
  {'min_ver' : '5.2', 'fix_ver' : '6.2(21)'},
  {'min_ver' : '7.3', 'fix_ver' : '8.1(1a)'}
  ];
}
else if ('UCS' >< product_info.device && product_info.model =~ "^6[123][0-9][0-9]")
{
  cbi = 'CSCve02461';
  version_list = [
  {'min_ver' : '0.0', 'fix_ver' : '3.2(2b)'}
  ];
}
else if ('Nexus' >< product_info.device) 
{
  if (product_info.model =~ "^(20|55|56|60)[0-9][0-9]")
  {
    cbi = 'CSCve02463';
    version_list = [
      {'min_ver' : '0.0', 'fix_ver' :'7.3(3)N1(1)'}
    ];
  }
  else if (product_info.model =~ "^90[0-9][0-9]")
  {
    cbi = 'CSCve02459';
    version_list = [
      {'min_ver' : '0.0', 'fix_ver' : '7.0(3)I4(7)'},
      {'min_ver' : '7.0(3)I5', 'fix_ver' : '7.0(3)I7(1)'}
    ];
  }
  else if (product_info.model =~ "^35[0-9][0-9]")
  {
    cbi = 'CSCve02459';
    version_list = [
      {'min_ver' : '6.0', 'fix_ver' : '7.0(3)I7(2)'}
    ];
  }
  else if (product_info.model =~ "^7[70][0-9][0-9]")
  {
    cbi = 'CSCvd69951';
    version_list = [
      {'min_ver' : '0.0', 'fix_ver' : '6.2(20)'},
      {'min_ver' : '7.2', 'fix_ver' : '7.3(2)D1(1)'},
      {'min_ver' : '8.0', 'fix_ver' : '8.1(2)'}
    ];
  }
  else if (product_info.model =~ "^95[0-9][0-9]")
  {
    cbi = 'CSCve02474';
    version_list = [
      {'min_ver' : '7.0', 'fix_ver' : '7.0(3)F3(1)'}
    ];
  }
  else if (product_info.model =~ "^30[0-9][0-9]")
  {
    cbi = 'CSCve02459';
    version_list = [
      {'min_ver' : '0.0', 'fix_ver' : '7.0(3)I4(7)'},
      {'min_ver' : '7.0(3)I5', 'fix_ver' : '7.0(3)I7(1)'}
    ];
  }
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
