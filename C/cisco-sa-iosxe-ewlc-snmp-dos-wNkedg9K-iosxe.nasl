#TRUSTED a7836f804ad60d8e293f92fa498d009681ba38f7e8470f24371dad655a5be15fc8a5a15e1d34b837b310496856ef1f00c272d03467342da21134d3325588e7929ede297c336f3ef81d7e66a158d84f3cf744fffbdacba9740433b13341786972a0933fcc8825a535538305c693b2dd141da4c0c9d88c1e1aed0e974e6b5c5c2a083a986ae71d01ac39842203b18da9af56693d0d4e06110f0d785bf528158a351e7270f6dac0e29a6b3994d318bf127d74a3ee272797f5c5d44b02f78fbfd1415e70cbe4513453968f3c6d426dd5f2f9876223499907f2cd6746845971fb1dd7050416b1e59264d57b1dc35027ad7eaaf266131e14595d0f5b8f2e3c620a2832d55335f4c682b200f3adb4799a90ac6bf99d270b4a0fa11da9cdd48983230cd45cae94641d8b1265166c94dc07bb28cfb265e201a3bf1963d9ef5bd7096b6354b35e940f3ffde18bee44a84d39dc4012b07a0e01fc71e4be90a1b929d2389f1a0b258a32d593aea0f079ed342ccc397d3f1813fc3a62f03391a60b43ab95f61f9f0778036715b716179a13babcda183c10db1a819b58ace6a5bfeb30d0b9b0c03f8cdbc9c93b7a13acd452686196ac5d25711118de111f5ef79eeb17b0c698aee2a4bf76601175b1777ff0e57da504656efe6b1d2a94024489d088f6a5e317e76a23b6c7d71f053375b8628193878d6e1cb423c9ebb16ed1cfea21a63b7df1dc
#TRUST-RSA-SHA256 9ba4d19a34bb400967c0306ed4dfb7a6ecc5501ccb1e5fbc9e70d4025b2cd0df7c8e84dbe7a14e373966581728465ddb1e4f4a70d1ff35bae7a3fc2a66ad44e98e593dc1539ce9a7e37942411405bda6f4eedd3bb4cf3df4942d70fe35e334c805374b6ccd13cff16ee6ca530618076b08f51ce83b3693a84e833e1beb75d88d97bbf5291edd4add4333e04ff4fc5924ae35b3b96ba9faf0c611b8e54ab939001c271440cb479660a229a657bd513fad84dffa5556effac1dc9642ab9b1a392dfce8751193bf4dd62c632d8640c9c5f96cb5564df7aa642c8cca29b5a664d9247403402a422c254144d42c6abc579bd5c9adfff44ae0db43c3afcaebf1030018d8d1236ca6bb2b3848d39aab0cd592f9364d6aa38ce0bc139c4489115a9495ddc2a9244b877e21a7dcc5ab0d424f96e5ea99d75721dc0a24a3f6fc5fb366a28420593a477dfdf7ec6384b07f009bd707d2fd4d8f24ecc5a72cd2c38e54c3d4286e092e583879fc7dfbc63900bdf41ea3288488482a165642f65ae62190bc28b88f55f6709e344b9cdbd0d882d8c2027c42bd919f4b00b403b2e64e0392ed575d1b53f3abe1c093af8fadd2066c13e97751fed7ed803a8b900ee841874edc71c663eb7c7d647a1d003ce27260bd06d01cee3f3e2b5b12d1f39a004247f38fbe6e0f559723895489042700468a33d4687426cb9cd2f9dfd45c99b03a1f11f9ba8e
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141266);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/07");

  script_cve_id("CVE-2020-3390");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs56562");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-ewlc-snmp-dos-wNkedg9K");
  script_xref(name:"IAVA", value:"2020-A-0439");

  script_name(english:"Cisco IOS XE Software Catalyst 9000 Family SNMP Trap DoS (cisco-sa-iosxe-ewlc-snmp-dos-wNkedg9K)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS XE Software is affected by a DoS vulnerability in the Simple Network
Management Protocol (SNMP) trap generation for wireless clients due to the lack of input validation of the information
used to generate an SNMP trap in relation to a wireless client connection. An unauthenticated, adjacent attacker could
exploit this vulnerability by sending an 802.1x packet with crafted parameters during the wireless authentication
setup phase of a connection and could cause the device to unexpectedly reload, causing a DoS condition. Please see the
included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-ewlc-snmp-dos-wNkedg9K
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e7ff3e30");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs56562");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs56562");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3390");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

if (product_info['model'] !~ "^(C)?9[13458]\d\d($|[^0-9])")
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_versions = make_list(
  '16.10.1',
  '16.10.1e',
  '16.10.1s',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.2',
  '16.12.1',
  '16.12.1s',
  '16.12.1t',
  '16.12.1z',
  '16.12.2s',
  '16.12.2t',
  '17.1.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['trapflags_client_dot11'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs56562',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:vuln_versions
);
