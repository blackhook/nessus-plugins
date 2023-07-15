#TRUSTED 2140ae675a84a617d4ed924bef87d76d7fc6111b3e849920f895982981fe1a47847499907e560ed5431098de94780914d9fc4b5efb4569c4d7c3acf1b4742c9eac1c3dc185ded6ed8917949f85699a02481be87b400f3b15b719fe934d927542ff92756eae2a7df7e864bbf779dc57682468a78c0d4efabc0e2cce9bf5f4b9d77310c278cbfc501f33c5fbf2c6da7c73868bc9623a3b555253ba2f61f7126acec14e12b722557bb7dba53116244f2c32e28de5ce575a93b617c699d3a5a0b6990363d5e9950efd9cf96fec55a6198ffc2aec7b70482e096c60068bd74f2ff9aa45354deebd03537d4d7f246b2f5e998e3281804f18a25429aa3841abd81ee569f8243339bb5326658a094649e6c0ea5f43abfdce2c7b895377b8582d38ea25bd25d8f5fb6fd3cf79eb94c2a46a43104ad7c4ac68c99a8d49dcc9efb26830a05985e8069388ae84330a3fbe037fc181d572cb8272e56b22edd668bc634f2c310aa33b8a551e384ed1833dcacd0e39c01ab66901494d0738b0264730aa720f95e32486b12dabde78e870b47dc49758ef5ad77a92402736ebe8144b840b13ee5ad31067f0e6c4e664d9e714efe1a98a237807825b2a71867c7ef917a554f83f608c59f395eb2ad85ea669eba1e3df62f14d53485f932b15351707fc2435cb2b81a0a4f36320c0fec637dd8e46472a87b016d2a9b7d83926c6edc2c7a78e83a3c73a
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133409);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2019-16019",
    "CVE-2019-16020",
    "CVE-2019-16021",
    "CVE-2019-16022",
    "CVE-2019-16023"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr74413");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr74986");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr80793");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr83742");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr84254");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200122-ios-xr-evpn");
  script_xref(name:"IAVA", value:"2020-A-0041-S");

  script_name(english:"Cisco IOS XR Software BGP EVPN DoS (cisco-sa-20200122-ios-xr-evpn)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR Software is affected by multiple denial of service (DoS)
vulnerabilities in the implementation of Border Gateway Protocol (BGP) Ethernet VPN (EVPN) functionality. These are due
to incorrect processing of BGP update messages that contain crafted EVPN attributes. An unauthenticated, remote attacker
can exploit these, by sending BGP EVPN update messages with malformed attributes to be processed by an affected system.
A successful exploit allows the attacker to cause the BGP process to restart unexpectedly, resulting in a DoS condition.

To exploit these vulnerabilities, the malicious BGP update message would need to come from a configured, valid BGP
peer, or would need to be injected by the attacker into the victim's BGP network on an existing, valid TCP connection
to a BGP peer. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200122-ios-xr-evpn
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ecf9b5c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr74413");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr74986");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr80793");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr83742");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr84254");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr74413, CSCvr74986, CSCvr80793, CSCvr83742, CSCvr84254.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16023");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-16022");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/31");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XR');

model = get_kb_item('CISCO/model');
if (empty_or_null(model))
  model = product_info['model'];
model = toupper(model);

if ('ASR9' >< model && 'X64' >!< model)
{
  pies = make_array(
      '6.6.2', 'asr9k-px-6.6.2.CSCvr91676'
  );
}
else if ('ASR9' >< model)
{
  pies = make_array(
      '6.6.1', 'asr9k-x64-6.6.1.CSCvr91660',
      '6.6.2', 'asr9k-x64-6.6.2.CSCvr91676',
      '7.0.1', 'asr9k-x64-7.0.1.CSCvr91676'
  );
}
else if ('NCS5500' >< model)
{
  pies = make_array(
      '6.6.1', 'ncs5500-6.6.1.CSCvr91660',
      '6.6.25', 'ncs5500-6.6.25.CSCvr91676'
  );
}
else if ('NCS540' >< model && 'L' >!< model)
{
  pies = make_array(
      '6.6.1', 'ncs540-6.6.1.CSCvr91660'
  );
}
else if ('NCS6' >< model)
{
  pies = make_array(
      '6.6.1', 'ncs6k-6.6.1.cscvr91660'
  );
}
else if ('XRV9' >< model || 'XRV 9' >< model)
{
  pies = make_array(
      '6.6.2', 'xrv9k-6.6.2.CSCvr91676'
  );
}
else if ('NCS560' >< model)
{
  pies = make_array(
      '6.6.25', 'ncs560-6.6.25.CSCvr91676'
  );
}

# Check for patches
version = product_info['version'];
if (!empty_or_null(pies) && !empty_or_null(pies[version]))
{
  fixed_ver = product_info['version'] + ' with patch ' + pies[version];
  if (get_kb_item('Host/local_checks_enabled'))
  {
    buf = cisco_command_kb_item('Host/Cisco/Config/show_install_package_all', 'show install package all');
    if (check_cisco_result(buf))
    {
      if (pies[version] >< buf)
        audit(AUDIT_HOST_NOT, 'affected since patch '+pies[version]+' is installed');
    }
  }
}

vuln_ranges = [
  {'min_ver' : '6.6.1', 'fix_ver' : '6.6.3'},
  {'min_ver' : '6.6.25', 'fix_ver' : '7.0.2'},
  {'min_ver' : '7.1', 'fix_ver' : '7.1.1'},
];

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['BGP_EVPN'];

if (!empty_or_null(fixed_ver))
  fixed_ver = fixed_ver + ' or upgrade to 6.6.3 / 7.0.2 / 7.1.1';
else
  fixed_ver = 'Upgrade to 6.6.3 / 7.0.2 / 7.1.1';

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr74413, CSCvr74986, CSCvr80793, CSCvr83742, CSCvr84254',
  'fix'      , fixed_ver
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  router_only:TRUE
);
