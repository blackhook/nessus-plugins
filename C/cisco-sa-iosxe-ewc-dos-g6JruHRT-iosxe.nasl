#TRUSTED 9cd72aace8577d07aabc139914f6e35e9af6cf783a408dda047aa31c5e70d2eba9dcf55b59dc89e1101fa761145913951aed8aafaf472dc1c652eae8675444f8099d42d865f25bc6343e4dff2395f3e8aab4f85e433cda1b21dacef50dc606628282f9bd5927105333bb2dde1b9b1f8bc71e7194fb6a422529256ad878ed1e0e442e4bed46e1465631a238da45f15420053e91a5c0770b24792875550a6b6428a26c54a4e3058b487292b75bac9b38c4ef6a8c10bededb4a7939dd48034eed64fde03d8948b89b8a98b44f96c46b835d248c75060faccb4dc30c1eb71bd34826dd4131adefa9249a5c00f89647e053fa101cfb2a4231e1b24a27cb432cd17de0bf9010f3fab7e935304149d4ee9bdaa5c7c6fcf89e16a81fc05fae3c595f4d77cee6129086115c178b0687fce9aab65a4405483d1a819a24496d6d50628992c861a6db481cac6c15095bb3757e593efc6cb75429516b698185e6d25f8146de07d80ecf07e32b68f25eddf7a663fac30d44ae2f5d5f446b588905fb75b4b420864b2cb88f8540339d3502ae6b3cbaa9af3df54c08e77512e497b8a47279cf7696f7fff1ee553eab65c197f31b63ed39d3d2c4a85c345368b3e635de45a9c32b1f810cfc2b29d0d369519ca89b97806210ee9cda62d33f9215841885c6d3d808813aefbd551ba868c74745d1632f3618cbb823f9c4418f3e1b37650fc0b94b5214
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153554);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/04");

  script_cve_id("CVE-2021-1615");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy04449");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-ewc-dos-g6JruHRT");

  script_name(english:"Cisco IOS XE Software Embedded Wireless Controller for Catalyst Access Points Denial of Service (cisco-sa-iosxe-ewc-dos-g6JruHRT)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in the packet processing functionality of Cisco Embedded Wireless Controller (EWC)
    Software for Catalyst Access Points (APs) could allow an unauthenticated, remote attacker to cause a
    denial of service (DoS) condition on an affected AP. This vulnerability is due to insufficient buffer
    allocation. An attacker could exploit this vulnerability by sending crafted traffic to an affected device.
    A successful exploit could allow the attacker to exhaust available resources and cause a DoS condition on
    an affected AP, as well as a DoS condition for client traffic traversing the AP. (CVE-2021-1615)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-ewc-dos-g6JruHRT
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c5440273");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74581");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy04449");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy04449");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1615");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(410);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var version_list=make_list(
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.2',
  '16.12.1',
  '16.12.1s',
  '16.12.1t',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '16.12.5',
  '17.1.1',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.2.1a',
  '17.3.1',
  '17.3.2',
  '17.3.2a',
  '17.3.3',
  '17.4.1',
  '17.5.1'
);

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvy04449',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info      : product_info,
  reporting         : reporting,
  vuln_versions     : version_list
);