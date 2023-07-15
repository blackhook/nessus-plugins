#TRUSTED 9acead695d25bcd0e102cd217b9f30bb1539cd648659b28b4a4784330867ffeb7a750e830121f3541aaadf2fc43de2ea59f6dafaa0ea23860038e11293eb40f2037076e058d7417217e48b2ce703b01d41325c08882be44f861ecff84c60cfbcacaf08f544bff64c9d787eafea7f94a96968ead19448f8fc124eefcd907d1505021c3fa5660622e185ab83dbe556df1e6ae4aa7471594b88d515751f2918ae7ddd4bee9f90c12a266f8cfebfa7a8fa7abc482fac36c7ee1f385284012019f6d7f101306d27a8ccc3feece531f29148044a7628e8f36b4d0e5342bdc89c8df390c7a40ffd5befa4dead0f926c591cb86f824d39944ebb1f80c3f2aa7fe1af470d24ade637d5cf01d0ba60eefa419be3d31b9c8a3836e3ebbeca65a673128da5b51c0a6100c6b2007629ef0ba002f7a62c6a8cacef34a1f08b634c0d29d35fc7e8bcc8d9d356316430754ed6639eddbf829286cb4d02b4b7c930de812e3a9b55159f86811e03091c9fa392cb448a07bbc949a0a42d5b6a63450e9c4071fe558eededea833f4f846af78f4a0ac357d4fd9ddc9ec2ed6413bf0bbb94095a9b1200cd2fdb8c42ea297e81068dfe75649cc017b20f25ac0be1bcb82076ceb9e71741925f9c41feb479725649ac2325b7d192c82c9806240efd220d2d504bf2666f7a92c1c7fe0e822f94866a28475dfb937a764e04c8e732cff107e6db1130eacfe0bf
#TRUST-RSA-SHA256 2698f5c733ddcc06946dfa273f0ca3cbc3aad509db27729a91ba16d0e4b4bebbce22a1ec6648d0607e4c8c25bbb64c630beacf99fffdc6a0197ae745bf54d16d4de2f3a20ab4c24a370782224e06310757e45305f5c191a0c71cece5440dd1595cc21a212221b51d6de99ad8fb2f470db55c28066ce195685540cdbc40e97bd165384ba63b1cedeb66b958bc5ec7779be0dcadfd43caabddfb0a71a20373c919acfd4bf80fd6fd2314bb1e1d5a74be12a95863b76786cad6f70bc245bbc71159be2aa0ac3637f57b6fb6864ede7fa47d40490cd2e7119c49d38a780dd4c848ea421140982ff26300dc92b2af6d4cae67ebb02244aff43a65f4e5fe2b1f17d9cef2609a3eabc3f595e0617c308d641931d2eb2c6feba4d1ce786428132394a5aa5817498e8c95d0abe763ec3eb892f7ee078508e85d0c651e95b7520158dbfad54484647ee01dad5a64402e3c96c4961c378a9ca864d518b2549a893190165e673b59136633f145a49f47e72ca36ab1e99fb22d3eb09154a2f105bc257e8a0177b6c2c7ea3876f1a77bec80e591916668d3cc212c8b0d32481858deedd375b8e7933be39c95774d49d06aaa7abcc86aa841e7674a8f7ef4e967e322d17180d0a115c1715cf8b0e52446468964086e5d248392ba9133bdf03cd48bc686cc6bae08ee8377c47d355149b086af845b794d8474e324b43335e9d6a538e6fa8d1721be
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165700);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-20848");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb18118");
  script_xref(name:"CISCO-SA", value:"cisco-sa-wlc-udp-dos-XDyEwhNz");

  script_name(english:"Cisco IOS XE Software for Embedded Wireless Controllers on Catalyst 9100 Series Access Points UDP Processing DoS (cisco-sa-wlc-udp-dos-XDyEwhNz)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the UDP processing functionality of Cisco IOS XE Software for Embedded Wireless Controllers on 
Catalyst 9100 Series Access Points could allow an unauthenticated, remote attacker to cause a denial of service (DoS) 
condition. This vulnerability is due to the improper processing of UDP datagrams. An attacker could exploit this 
vulnerability by sending malicious UDP datagrams to an affected device. A successful exploit could allow the attacker 
to cause the device to reload, resulting in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wlc-udp-dos-XDyEwhNz
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e8c155a");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74745");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb18118");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwb18118");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20848");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var model = toupper(product_info.model);

# Vulnerable model list
if ('CATALYST' >!< model || model !~ "9100")
   audit(AUDIT_DEVICE_NOT_VULN, model);

var version_list=make_list(
  '17.6.1',
  '17.6.1a',
  '17.6.1w',
  '17.6.1x',
  '17.6.1y',
  '17.6.2',
  '17.6.3',
  '17.6.3a',
  '17.7.1',
  '17.7.1a',
  '17.7.1b',
  '17.7.2',
  '17.8.1',
  '17.8.1a'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [WORKAROUND_CONFIG['show_wireless_ewc-ap_redundancy_summary']];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwb18118',
  'cmds'    , make_list('show wireless ewc-ap redundancy summary')  
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
