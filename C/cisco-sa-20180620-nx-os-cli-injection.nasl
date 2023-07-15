#TRUSTED 2cdb31e930a06857b646bd7e6b48f3e440e1908e328a23a4b9df2a43130739d9023aeaff6293f4a052a4dd3eaaa16292f205e64333bfee433987b97f240852c52a4393e884d6133d8d53262e0545c3265d34c1a99482abd876fd5adc36995b21c224fed639b17cb5711461f97f426b9fb4306f6cfdd547d52a58720ac24b83ff05043e3a835833e4e56eec5f23e15aaf87263b585009bc275d24b763d0354841df94fdb05b7bf87ac2b0f6b2638e588c9f1ad0d4df543eef2bcf3c284a89d329fcaa41bfe1e72e671c5cf64cef0622fb7501036ad798cc38612d867f945cf1581a9e0ee999c3ed3849a1b7acfa926fce1885bd43000c57b69ef0acb4f464bb5a2b0c30986fd0865a685dd6471eefa49b60753c6f8becb86333559e622998a01b26136bcdb4565ca77ce6f39d6a1177e81d411439749b81f2e8b7f7d040a5452d730b5b90c8ea20a1fc810eae7bcc3eea876aab295121f6c9bb09c76d198e2b6b061849973aa81a327b189bcdf3e4cb4e448c8f55a13950690873d3dd34c5dbb5a00457a35cef7070ed9432a6635e1e10535dc183bdd074a1a2822ee1bb4c95e755885b75c38b16a9e630b574c28e75ace0ff3ec8e82f8d8aa654872f8fa5ffd27039c6b8057df62e692f447f4aff4da6dd5acb96ea0ad072491d2701b247a7c53ebffaca77873fe6bbeb5df5f993e62907f226938788663a7265e83ae4cd9537
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138437);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/04");

  script_cve_id("CVE-2018-0307");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve51704");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve91749");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve91768");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-nx-os-cli-injection");
  script_xref(name:"IAVA", value:"2020-A-0397");

  script_name(english:"Cisco NX-OS Software CLI Arbitrary Command Injection (cisco-sa-20180620-nx-os-cli-injection)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A command injection vulnerability exists in the CLI of Cisco NX-OS Software due to 
insufficient input validation of command arguments. An authenticated, local attacker 
can exploit this, via a vulnerable CLI command to execute arbitrary commands.

Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-nx-os-cli-injection
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38e5ac5c");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-67770");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-67770");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve51704");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve91749");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve91768");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCve51704, CSCve91749, CSCve91768");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0307");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/14");

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

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >!< product_info.device)
   audit(AUDIT_HOST_NOT, 'affected');

bid = '';
version_list=make_list('');

if ('Nexus' >!< product_info.device) 
  audit(AUDIT_HOST_NOT, 'affected');

if (product_info.model =~ '^(30[0-9][0-9])')
{
  bid ='CSCve51704';
  version_list = [
    {'min_ver' : '0.0', 'fix_ver' : '7.0(3)I4(8)'},
    {'min_ver' : '7.0(3)I5', 'fix_ver' : '7.0(3)I7(1)'}
  ];
}
else if (product_info.model =~ '^(35[0-9][0-9])')
{
  bid ='CSCve91749';
  version_list = [
    {'min_ver' : '6.0', 'fix_ver' : '6.0(2)A8(6)'},
  ];
}
else if (product_info.model =~ '^((20|55|56|60)[0-9][0-9])')
{
  bid ='CSCve91768';
  version_list = [    
    {'min_ver' : '6.0', 'fix_ver' : '7.1(5)N1(1b)'},
    {'min_ver' : '7.2', 'fix_ver' : '7.3(3)N1(1)'}
  ];
}
else if (product_info.model =~ '^((7[70])[0-9][0-9])')
{
  bid ='CSCve51704';
  version_list = [
    {'min_ver' : '6.2', 'fix_ver' : '6.2(20a)'},
    {'min_ver' : '7.2', 'fix_ver' : '7.3(2)D1(3)'},
    {'min_ver' : '8.0', 'fix_ver' : '8.1(2)'}
  ];
}
else if (product_info.model =~ '^(90[0-9][0-9])')
{
  bid ='CSCve51704';
  version_list = [
    {'min_ver' : '0.0', 'fix_ver' : '7.0(3)I4(8)'},
    {'min_ver' : '7.0(3)I5', 'fix_ver' : '7.0(3)I7(1)'}
  ];
}
else if (product_info.model =~ '^(95[0-9][0-9])')
{
  bid ='CSCve51704';
  version_list = [
    {'min_ver' : '7.0', 'fix_ver' : '7.0(3)F3(3a)'},
  ];
}
    
if (bid == '')
  audit(AUDIT_HOST_NOT, 'affected');
    
reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , bid
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:version_list
);
