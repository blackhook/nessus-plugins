#TRUSTED 11178ae1fbcf4aad0195c751d043883a772d3d99ffbda60dadccda55cac43ae524879408bb76c2ebe48104913ddfd02289b74ef0e776a196ed5cd37639ab02959ac2df4aaa843bac7c0c8831c6c1ceb256def8393c9b017bef0e0651de165f0459ae1d3e6ae55518bdf79e6141880b1de8d531e68c8502ac1eae89b7022fa18564988f6b9dc7d6b36ced6438a97ba228b957a52f0a6e459b49cd36563fd14a76f26d9cd508b20ae31d47bbb716b779f9ebd734970488fc0ff2ae2cac76df791fadcff388d1f3af3413a28d5f0817da8a75df4a309ff261eb66953316596d8d96e2e68f34287617de03af00d45decd3fe0c6c44415ce1cd013075e6da0f3f7d1af59b2f7bbc8e332660c00ce0c0bb5efe5e8bccb8b4eccfb2f12e4505b940309b7d59d6d80a5e7fca132ec1ce9bd82900b1a99f4c7fa1ea2b2bf8b41e4e746a88204bbc5534b97fa91c2db9b0c547674692fec1c4758d35358cda625355a157da08bccd8eb13497f826b7d5ebd9e8ca4569e0a588d138cdeb61dbf4349b8ec17d6b3dabf1bc8be83c1245d097e43d44fd6b9b4f2cfbf794cc4810f906880dbd2593f2e5c0c9da09c0d752d87c16d860e1cbe6b5964dddffc7e4ef22cef6d2ddb5b85d8e25ecba9627108eecf332fd73c269a5fd17b299d0895867b330fa7acbe95b0deb1ec7f70a3b2540f1fdd9cc6aaaa20ae1adb19f7e36eb73f07a1367815a
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130597);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/29");

  script_cve_id("CVE-2016-1454");
  script_bugtraq_id(93417);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq77105");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux11417");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20161005-bgp");

  script_name(english:"Cisco NX-OS Border Gateway Protocol DoS (cisco-sa-20161005-bgp)");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, a denial of service (DoS) vulnerability exists in the Border Gateway Protocol
(BGP) implementation of Cisco NX-OS System Software due to incomplete input validation of BGP update messages. An
unauthenticated, remote attacker can exploit this issue, by sending a crafted BGP update message to the targeted device,
to cause the switch to reload unexpectedly. As the Cisco implementation of the BGP protocol only accepts incoming BGP
traffic from explicitly defined peers, an attacker must be able to send the malicious packets over a TCP connection
that appears to come from a trusted BGP peer or be able to inject malformed messages into the victim's BGP network.
This vulnerability can only be triggered when the router receives a malformed BGP message from a peer on an existing
BGP session, so at least one BGP neighbor session must be established for a router to be vulnerable.

This vulnerability is not remotely exploitable if all BGP peers to the NX-OS Software are Cisco IOS, IOS-XE, or IOS-XR
device and those device are not configured for Cisco Multicast VPN (MVPN) interautonomous system support.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161005-bgp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3be03020");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuq77105");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCux11417");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCuq77105 or CSCux11417.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1454");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

get_kb_item_or_exit('Host/Cisco/NX-OS/Device');
get_kb_item_or_exit('Host/Cisco/NX-OS/Model');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');
product_info.version = toupper(product_info.version);
product_info.model = toupper(product_info.model);

if ('Nexus' >!< product_info.device)
  audit(AUDIT_DEVICE_NOT_VULN, product_info.device);

# Don't check for ([^0-9]|$) at the end of the regex because, according to the Cisco Software Download pages, for
# example, Nexus 9000 Series Switches includes the 92300YC switch.
if (product_info.model =~ '^10[0-9]{2}V')
  vuln_ranges = [
    {'min_ver' : '0.0', 'fix_ver' : '5.2(1)SV3(1.15)'}
  ];
else if (product_info.model =~ '^30[0-9]{2}')
  vuln_ranges = [
    {'min_ver' : '0.0', 'fix_ver' : '6.0(2)U6(7)'},
    {'min_ver' : '6.1', 'fix_ver' : '7.0(3)I2(2E)'}
  ];
else if (product_info.model =~ '^35[0-9]{2}')
  vuln_ranges = [
    {'min_ver' : '0.0', 'fix_ver' : '6.0(2)A6(8)'}
  ];
else if (product_info.model =~ '^50[0-9]{2}')
  vuln_ranges = [
    # Advisory says prior to 5.2 and 5.2 are affected with no fix available, so passing 5.3 as the fixed version
    {'min_ver' : '0.0', 'fix_ver' : '5.3'}
  ];
else if (product_info.model =~ '^[26]0[0-9]{2}' ||
         product_info.model =~ '^5[56][0-9]{2}')
  vuln_ranges = [
    {'min_ver' : '0.0', 'fix_ver' : '7.1(1)N1(1)'},
    {'min_ver' : '7.2', 'fix_ver' : '7.2(0)N1(1)'},
    {'min_ver' : '7.3', 'fix_ver' : '7.3(0)N1(1)'}
  ];
else if (product_info.model =~ '^7[07][0-9]{2}')
  vuln_ranges = [
    {'min_ver' : '0.0', 'fix_ver' : '6.2(10)'},
    {'min_ver' : '7.2', 'fix_ver' : '7.2(0)D1(1)'},
    {'min_ver' : '7.3', 'fix_ver' : '7.3(0)D1(1)'}
  ];
else if (product_info.model =~ '^90[0-9]{2}')
{
  # We need to distinguish between Nexus 9000 Series Switches in ACI vs. NX-OS mode. From the Cisco Software Download
  # pages, it looks like ACI mode versions are always formatted like ab.c(dA) where abcd are integers and A is any
  # letter of the alphabet. NX-OS versions are never formatted like this.
  if (pregmatch(icase:TRUE, pattern: "[0-9]+\.[0-9]+\([0-9]+[A-Z]+\)", string:product_info.version))
    # ACI mode
    vuln_ranges = [
      {'min_ver' : '11.0', 'fix_ver' : '11.1(1J)'}
    ];
  else
    # NX-OS mode
    vuln_ranges = [
      {'min_ver' : '6.1', 'fix_ver' : '7.0(3)I2(2E)'}
    ];
}
else
  audit(AUDIT_HOST_NOT, 'vulnerable');

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['nxos_bgp_neighbor'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , cbi
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_ranges:vuln_ranges, 
  switch_only:TRUE
);

