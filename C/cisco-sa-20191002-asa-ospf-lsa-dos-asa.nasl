#TRUSTED 89016bf3a32919416cd520ec41f6362a061718f94b85a0ba39f7e841e8daa0987b0e008ec1a8328dc9e3c16219b07f80d2cd2d044c5d561ed644d349ddf97e077ebeee07b9a0e6bbdcbd3bd277aeb2ecbd9ecc12086c185f8323eb5bf02431f73f9f4b089c25c71115f336fca93d6adcf9d9d6d48e8e86d22f39dc9d7dbdcaf13f8fa1dd33146fdf1180bb3fb6e422c6250a19922f243ec68d9e9fe2e061f66ebffb88598fa3565a3368fab17dc04927e546ea6d6cb7520a558455f2d78be624cc08624ca57e70945c29e104e5acfb608799dd1fc9da3035b78e47ffa17f1ba892e02e7643aa3c0191a698b3f6cd3844e20fbdee9ec60712e2fe73d72e34b9c4bb58b6b218f8b2dd8ed8d8be44e7b4319de309d4e730ffb7f85da208652b339a8ca290e827d4ed94c0a1a8f5f300833b49e65f6c92ce26213dfcf2b3687ea10d4ec719a7895da96be799c19db116754fd411b59401e46f4915bbe7180e90d4eb3ea61d7aa6663b34eebcb84dcf571e809a8104fff943d28344baef90daa540dbb012e05dd5310099128107d324373a66c31032f33e419cc0e07c01b3f9ead5a5f84c770ab3ffb767e38113804d08416ad21e2eb311247f23858bca3bd0f85c28f884fac90be3e7f964678ddba452c7795b15663edd49a0fc33e67e0f62956d24daafdd930fe308b30554a7a6e5cf89c08485604d5256aa2eba37f1a3d9d6582b
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138024);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/06");

  script_cve_id("CVE-2019-12676");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp49790");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191002-asa-ospf-lsa-dos");

  script_name(english:"Cisco Adaptive Security Appliance Software OSPF LSA Packets Processing DoS (cisco-sa-20191002-asa-ospf-lsa-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Adaptive Security Appliance
(ASA) Software is affected by a vulnerability in the Open Shortest
Path First (OSPF) implementation due to incorrect processing of
certain OSPF packets. An unauthenticated, adjacent attacker can
exploit this by sending a series of crafted LSA type 11 OSPF
packet to an affected device, causing a reload of the affected
device, resulting in a DoS.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191002-asa-ospf-lsa-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?192e9e54");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp49790");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp49790");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12676");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

vuln_ranges = [
  {'min_ver' : '0',  'fix_ver' : '9.6.4.34'},
  {'min_ver' : '9.7',  'fix_ver' : '9.8.4.8'},
  {'min_ver' : '9.9',  'fix_ver' : '9.9.2.59'},
  {'min_ver' : '9.10',  'fix_ver' : '9.10.1.27'},
  {'min_ver' : '9.12',  'fix_ver' : '9.12.2.1'}
];

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['asa_ospf'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvp49790',
  'cmds'     , make_list('show ospf')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
