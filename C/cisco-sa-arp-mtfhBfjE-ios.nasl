#TRUSTED 7ce83399867366c9c93199f1b06be0370349eee9bcdf71cda24a84dbf2507efabc97775ba3661d612c1d1909d2847b994a5f0d002618cb09ec2cf8908032a840723a88c785080f4734546b2012d2a0201f57bfaa9731d807cde789308e68d7d3785d167391600a17815f3d0a62036a9ee6cbc166091e3045ac5909d56c54f7059aaa8cd8b67898ed07803b92f18e3b17cdc2bb2eb9f09132772e8bfd834c6a77ce740e6402a2bd5365500c7e7ab584595983d912c393fb43578f03a98f9fd0b6e4a33d3bce4239e4f7ec0979a774d282b2e9e454cdb90c860bf7f79b0917ce8bf80c177491fee0adafedb38e824b1ceb28da204cd0e233108785073676bf7523e3d27ed034cfe89baca8b5c195eed7d5bc29139b2ae19ea12f3aa754dc1e426300381c987246bbc58ccd7a740f979856f993b193eeafd4ca0bb925bccc7711fc6f2cc9d6258b78043ed473856973086f144851ab1a60502118f04946f6bed96d39304e3077f057ac8099475fdbb0c08a1f4de94cc9653b51f5644a7c727d65cac7a8f3c1e59379218425da8587028858532a54643dce98bacb4637a360a54b1bb1135f677bf47be36394d49d8a05f08669cb60846e8174681c57ff67d784602ba2a90ab619463ecc049babe8d35e9579de677ab7c22ca3b58ee43f8d3bf3d30bfeceb72f468878d42583d0c4be620c6452868a2ceb391e26f1434c632c696de9
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148223);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/09");

  script_cve_id("CVE-2021-1377");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv75175");
  script_xref(name:"CISCO-SA", value:"cisco-sa-arp-mtfhBfjE");
  script_xref(name:"IAVA", value:"2021-A-0141-S");

  script_name(english:"Cisco IOS Software ARP Resource Management Exhaustion Denial of Service (cisco-sa-arp-mtfhBfjE)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in Address Resolution Protocol (ARP) management of Cisco IOS Software could allow an unauthenticated,
remote attacker to prevent an affected device from resolving ARP entries for legitimate hosts on the connected subnets.
This vulnerability exists because ARP entries are mismanaged. An attacker could exploit this vulnerability by
continuously sending traffic that results in incomplete ARP entries. A successful exploit could allow the attacker to
cause ARP requests on the device to be unsuccessful for legitimate hosts, resulting in a denial of service (DoS)
condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-arp-mtfhBfjE
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?39afa1f0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv75175");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv75175");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1377");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

version_list=make_list(
  '12.2(6)I1',
  '15.1(3)SVR1',
  '15.1(3)SVR2',
  '15.1(3)SVR3',
  '15.1(3)SVS',
  '15.1(3)SVS1',
  '15.2(2)E6',
  '15.2(2)E7',
  '15.2(2)E7b',
  '15.2(2)E8',
  '15.2(2)E9',
  '15.2(2)E9a',
  '15.2(2)E10',
  '15.2(3)E5',
  '15.2(4)E4',
  '15.2(4)E5',
  '15.2(4)E5a',
  '15.2(4)E6',
  '15.2(4)E7',
  '15.2(4)E8',
  '15.2(4)E9',
  '15.2(4)E10',
  '15.2(4)E10a',
  '15.2(4)EA6',
  '15.2(4)EA7',
  '15.2(4)EA8',
  '15.2(4)EA9',
  '15.2(4)EA9a',
  '15.2(4)EA10',
  '15.2(5)E1',
  '15.2(5)E2',
  '15.2(5)E2b',
  '15.2(5)E2c',
  '15.2(5)EX',
  '15.2(5a)E1',
  '15.2(6)E',
  '15.2(6)E0a',
  '15.2(6)E0c',
  '15.2(6)E1',
  '15.2(6)E1a',
  '15.2(6)E1s',
  '15.2(6)E2',
  '15.2(6)E2a',
  '15.2(6)E2b',
  '15.2(6)E3',
  '15.2(6)EB',
  '15.2(7)E',
  '15.2(7)E0a',
  '15.2(7)E0b',
  '15.2(7)E0s',
  '15.2(7)E1',
  '15.2(7)E1a',
  '15.2(7)E2',
  '15.2(7)E2a',
  '15.2(7)E2b',
  '15.2(7)E3',
  '15.2(7a)E0b',
  '15.2(7b)E0b',
  '15.3(3)JPC97',
  '15.4(1)SY',
  '15.4(1)SY1',
  '15.4(1)SY2',
  '15.4(1)SY3',
  '15.4(1)SY4',
  '15.5(1)SY',
  '15.5(1)SY1',
  '15.5(1)SY2',
  '15.5(1)SY3',
  '15.5(1)SY4',
  '15.5(1)SY5',
  '15.5(1)SY6',
  '15.5(3)M4',
  '15.5(3)M4a',
  '15.5(3)M4b',
  '15.5(3)M4c',
  '15.5(3)M5',
  '15.5(3)M6',
  '15.5(3)M6a',
  '15.5(3)M7',
  '15.5(3)M8',
  '15.5(3)M9',
  '15.5(3)M10',
  '15.5(3)M11',
  '15.5(3)S4',
  '15.5(3)S5',
  '15.5(3)S6',
  '15.5(3)S6a',
  '15.5(3)S6b',
  '15.5(3)S7',
  '15.5(3)S8',
  '15.5(3)S9',
  '15.5(3)S9a',
  '15.5(3)S10',
  '15.5(3)S10a',
  '15.6(3)M2',
  '15.6(3)M2a',
  '15.6(3)M3',
  '15.6(3)M3a',
  '15.6(3)M4',
  '15.6(3)M5',
  '15.6(3)M6',
  '15.6(3)M6a',
  '15.6(3)M6b',
  '15.6(3)M7',
  '15.6(3)M8',
  '15.6(3)M9',
  '15.7(3)M',
  '15.7(3)M0a',
  '15.7(3)M1',
  '15.7(3)M2',
  '15.7(3)M3',
  '15.7(3)M4',
  '15.7(3)M4a',
  '15.7(3)M4b',
  '15.7(3)M5',
  '15.7(3)M6',
  '15.7(3)M7',
  '15.8(3)M',
  '15.8(3)M0a',
  '15.8(3)M0b',
  '15.8(3)M1',
  '15.8(3)M1a',
  '15.8(3)M2',
  '15.8(3)M2a',
  '15.8(3)M3',
  '15.8(3)M3a',
  '15.8(3)M3b',
  '15.8(3)M4',
  '15.8(3)M5',
  '15.9(3)M',
  '15.9(3)M0a',
  '15.9(3)M1',
  '15.9(3)M2',
  '15.9(3)M2a'
);

reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvv75175',
  'version'  , product_info['version'],
  'disable_caveat', TRUE

);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
