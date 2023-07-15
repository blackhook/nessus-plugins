#TRUSTED 9e327946e557d9647299b0f657e7fa455f7bc48692880f2eb5ff51a95d958a03258d97ed1c35970add6477dc813bd83cef1dca8e7f35222e218dde12b20ab64b08d3640011b9546f5b47d4d87245ec255d59280bd7c61ea824f35c89c32d5ae0f950a65f5d2bd46e24f9f3d0af9fb58c828b2d7645a5de1ed9ee0b9967b7019f15056e7af6d92595f7281b8a78937dceb4a99303ec22434288c6d355e07ec6e600abcdcc3c2c438726cd2e89b3b245d776d4ed6276095ec7edc43b1306588cd91b0d61654567fb76775953e9b0aeaa8a6ae14c4495623bf77125174d099b84d54fdce85da8b2b6ed3484a1eefc52905fb5dd6ec6a2482353a9016af9884d8e38ab2d58ed713e2e2f42f39f3b9b243db0c20f8e9553d0308f664d545800a54f6af7a0bcd8df9f53abd1a536f8f19097ede70119b657bd41d50d2119ccfbf14f3ec0200fa1205bcb750ed5ae12a43a7f8d5a61f41276fbf6404a788abcbe8494da16e25696a55a026ae7b9655a402036db7d7be3aa6fb239643b6f3c18917d9e75f3e904a82d7a581ded3ae57f20e22461d72fafe4e18524d66c5a3cb89eec9558d716112e70919912d4cc32499f3084445e84a33c8a772d8e112506836c583eef74db0e16f1748229d58723cf232a7e3f5f275e4bfc1a61525479a2732a453965c2b737e9cf56b2fd5ac97e0894696a94d7d98205dbcd62b9934767a1096eb282
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138355);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/10");

  script_cve_id("CVE-2019-1615");
  script_bugtraq_id(107397);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj14135");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk70903");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk70905");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190306-nxos-sig-verif");

  script_name(english:"Cisco NX-OS Software Image Signature Verification (cisco-sa-20190306-nxos-sig-verif)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software for Nexus 9000 Series Fabric 
Switches ACI Mode is affected by a denial of service (DoS) vulnerability exists in Fibre 
Channel over Ethernet N-port Virtualization due to incorrect processing of FCoE packets. 
An unauthenticated, adjacent attacker can exploit this issue, via sending a stream of 
FCoE frames, to cause the system to stop responding. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190306-nxos-sig-verif
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bf14d312");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-70757");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj14135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk70903");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk70905");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvj14135, CSCvk70903, CSCvk70905");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1615");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device", "Host/aci/system/chassis/summary");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >!< product_info.device)
  audit(AUDIT_HOST_NOT, 'affected');
else if (product_info.model =~ '^([39]0[0-9][0-9])' && empty_or_null(get_kb_item("Host/aci/system/chassis/summary")))
  {
    cbi = 'CSCvj14135';
    version_list = [
    {'min_ver' : '7.0', 'fix_ver' : '7.0(3)I7(5)'}
    ];
  }
else if (product_info.model =~ '^(90[0-9][0-9])')
  {
    cbi = 'CSCvk70903';
    version_list = [
    {'min_ver' : '0.0', 'fix_ver' : '13.2(1l)'}
    ];
  }
else if (product_info.model =~ '^(95[0-9][0-9])')
  {
    cbi = 'CSCvk70905';
    version_list = [
    {'min_ver' : '7.0(3)F1', 'fix_ver' : '7.0(3)F3(5)'}
    ];
  }
else 
  audit(AUDIT_HOST_NOT, 'affected');

bios = '';
var buf = cisco_command_kb_item("Host/Cisco/Config/show_inventory", "show inventory");
if (empty_or_null(buf))
    audit(AUDIT_HOST_NOT, 'affected');
if (buf =~ 
 "N9K-C9(2160YC-X|2304QC|232C|236C|272Q|3108TC-EX|3120TX|3128TX|3180YC-EX|332PQ|372PX|372PX-E|372TX|372TX-E|396PX|396TX)|N3K-C31128PQ-10GE")
    bios = "BIOS: version 0([1-6]|7\.([0-5]|6[0-2]))";
if (buf =~ "N9K-SUP-[AB]|N3K-C3(132C-Z|164Q-40GE|232C|264Q)")
    bios = "BIOS: version 0([1-7]|8\.([0-2]|3[0-3]))";
if (bios == '')
        audit(AUDIT_HOST_NOT, 'affected');
var buf = cisco_command_kb_item("Host/Cisco/Config/show_ver", "show version");
if (empty_or_null(buf))
    audit(AUDIT_HOST_NOT, 'affected'); #Something is very wrong if this has happened.
if (buf !~ bios)
    audit(AUDIT_HOST_NOT, 'affected');
reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , cbi,
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:version_list
);
