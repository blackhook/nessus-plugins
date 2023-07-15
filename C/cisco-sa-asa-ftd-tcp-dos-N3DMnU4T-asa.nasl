#TRUSTED a014f440153e29531bda5e7381da24a57e6dfe919c0d625bd6e171550d1f1f2685eac89cc6bb9efbea7990fd275a4833e3c5d59a0eb2d14af67d39c2da1f5ec9c610ce6f0cc5d338a09157cb216519d2a9690046d5e0ec04ade6b25c7ff5f7f2e9f5cd1a1cc63a8f487928c1b61422587824c83f9a4797272f8673f2e206b5cf3fbcaff100dd16fe8f5b09d608d4b88f839888721b4caab4084ae7d4c8d55e06264795300d05447d16d7f987403deac66e6e9a2412529692962c50bede88f760d00553694628da119775774f5caae9a8b9f7cacabd4d8c1a1628614447d1b8477fabdbf9e37816c134f3284214c3daab29f5a3159e8eb2452973e2cf60d60c0f4d6402ab3d0b35d9dc6610325e8fbea0867d3d31aa0fca123eb3f87c05a06c524de4ed8b81a3cd1cca0042f882b24e60f8659ecf5f8d594e0103b8c77f467dd270280200cf60b641d81e1b1f7c937f31a3a52cd2931ccd5fc00528d6f411b55a82e11577ed57748d1f177eaf43599c803f5a87ff118f9b236fdbd0003fac435d899cd766ae79a8b0b8e78b6ce9281f492d693974550151b3458aeea8e89c2aa4fb6f338c8be9d3273e12a5df62c336c9939e516ac59a3a1c30cd964fcbf196af8bddbc1acc0f30b0382f883d6b9bfd285b23ef5b1135ab6081643c31eeb23ff2ba53dd22612176dc4a0fc7aeac98965093a530f24ea42d611e66fc44a7d30362
#TRUST-RSA-SHA256 6e5519f7ac3426588b4fb60e2b91d1f48b2d7e1c7762235d65fcc8ea4a3a08f4a1f26323140c25844548c4ca07d2824b76be6403bbc579bc04bbe3ed6f90f69b2453ca66edbd74b418fc18c6059ea13f8ca4d52167ed93141ebef2ec597a46111e7d70fb55eaca5922664a40a369e743df5846a84187586d916bd6d70268b0f8b47059dc00bd7e749f8dc0be082f90b3f90300b93cc7a802e3b5bb3cf26f04910ecf382d4c8c215c5e134c59c41d50716cf7321b058fd1168b5b53246207179bd3eef3ca3724b86fa3cf79236bfa607969512e3f91d6ced3be496b7414c6b12fcf256d07438441aab5128043e8559f7fb0f2215a9de2b2d1f1c173c92c6e9efa4a2e312ede6eaecf63165641f8197df8a9f77ef3b7bc4f0ede1bb5c59dba5ca4d5f57dd3f01f648804ff4bff5a67dc25b36400a245bc79db9a5631b3718da0b86931c2908b12891233d018568131da803c2f330fc3b4bcea7109bf2b99137e402f16729a9cc7f6b9e419d50bacb7983337998627a056a93b29dcf33982c057e85a83edd41c6602edb54dadb4e0e7e567742d15ec59471aadc5ba2f8e40ef526e84a8c03cf97a558cdca1aef47801071cec4fb1df76e845b9affc9668a17789555935dbf93bb73009cf695d76e6ed37ef36630aaceb1f6602c43f4e535fe326449412787b19ffdc33b36331c176e530fa94d387ca7b62e8016ef23f5008606240
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149314);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3572");
  script_xref(name:"IAVA", value:"2020-A-0488-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu46685");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-ftd-tcp-dos-N3DMnU4T");

  script_name(english:"Cisco Adaptive Security Appliance Software SSL/TLS Session DoS (cisco-sa-asa-ftd-tcp-dos-N3DMnU4T)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the SSL/TLS session handler of Cisco Adaptive Security Appliance Software (ASA)
is affected by denial of service vulnerability due to a memory leak when closing SSL/TLS connections in a specific 
state. An unauthenticated, remote attacker can exploit this by establishing several SSL/TLS sessions and ensuring they 
are closed under certain conditions. A successful exploit could allow the attacker to exhaust memory resources in the 
affected device, which would prevent it from processing new SSL/TLS connections, resulting in a DoS. Manual intervention 
is required to recover an affected device.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-ftd-tcp-dos-N3DMnU4T
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?574e4ada");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74302");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu46685");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu46685");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3572");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '9.6.4.45'},
  {'min_ver' : '9.7', 'fix_ver' : '9.8.4.26'},
  {'min_ver' : '9.9', 'fix_ver' : '9.9.2.80'},
  {'min_ver' : '9.10', 'fix_ver' : '9.10.1.44'},
  {'min_ver' : '9.12', 'fix_ver' : '9.12.4.4'},
  {'min_ver' : '9.13', 'fix_ver' : '9.13.1.13'},
  {'min_ver' : '9.14', 'fix_ver' : '9.14.1.19'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['show_asp_table_ssl_dtls'];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu46685',
  'cmds'     , make_list('show asp table socket')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
