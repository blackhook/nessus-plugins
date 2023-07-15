#TRUSTED 8afc8ea44beb3f80692cac0272ae1aa8ef01ceb98899216cb3669348d28773473f595324598469e5afc941e4ff24493d8186dbc7681448c70bdcdb5052d9c02427f138cb1144c6e47828e3e09921f5ed4cef1e2a1ec1352b1f4a1bb5cd6deb7fa15d68ae2ceaa222f3afc2c7d235c046ee64db2dfeb083a83d3356098f76fbf537b2fc1891e3d1d90fe7e514496ac807db133f70bea7c574b51191ffccdf82d9122e715965147bb7fdd63120a66ad64e3cd6504f1f08c0b5a54f2eb9bf156ffbd5b365f6a731153893c94800b40b0d5c906bc18d864152bdb4039e633476e2b6c4282d081bcb3dd9060580a0e0d5335d696810ad2540c452c67d2c535ae35ce8949f0ccf1cd26bbe2e282c7738f3ef4d49095fad70e2994961eda75c2ff7fea06a322c0668a5dcb200fdff49cb20783f4a76f95152997e60f0c0afd5c51a9cbe5f05449ac0dda9092b6579ed0ce1d91cf537b3f244d5d359f77e8948377ec1fa649afbdaf02333582b3eed8c0b54f73ee73197f61d76b22c7ccb600ed1d5369cdb621f2657739de1855321506c20330d89fd6bbcf869827a5d282f1c1223c1ca6e87002e8337c60467e668a8cb2808adab070895d717a622fc4b28af1668b87ae7fab0292d046ba4fb2756ce77b36cc39247dfa7cb620fddffe74daf28f27af38fcb06339878bd0b5bc88ddbdaed1982df2eed201e58ad023059e7e298a3f997
#TRUST-RSA-SHA256 86a6502eeb47ec8c1ed1c7be853c8662c1589431c7016b1c40a7861e7cfe6c5ff87712cb85fffc9ecfa2cd71b798f4034fac268711e6c5a67ae356011c61d8b42d73920abe7d846cfc112776dd4243ad4eff85251da658fa7b5bbbf5f33004680aca84b5abdc2a539d5d0b427687fcf30ff757ca97ff726583278c23f392c9d68c95cf677f4fb818e00d2fe434a83a24992d8c75a05acf1dbd8cb8e4f1e6de82806150412ffb72583ba57f8f17d575696026a70cec8242a805188dedc68aa467279f23844b4e305729b2d5afcf0a0304c57f4f18938c780bc5c039043c94be193eacd4798e96bcaf6648fe9dec21432dea038633445bdee0473e2a144e77efe27fd2cb72446134f1de5dee2b4f02934082171b5786e1c08bd7ae96cb34466475ecfc72e3264d5c59873961d690a38100bad08442cc37d4b65353ac55cdb9e52df415fb794f72d2018abb4b251dd98d3fc9501eded636fa85e7b2fbd5285fd2aecd82159349800be23a45e30d09cc5b5da6c9b6dd224a7eec49ab03e53ee8fc8175ecd1735639d34a8bf8491ce0ad033b79cd4133252cf8d212949e0b9a886c1437dbe1b5c0a03449ff6b1d0c9056bd49440066bf6366a40e6c03751ab45adf23109244a8fc13af0e39e1abb4bcee76ac64e76bad3f23eb41aa57c1c7374846d646eda37e5b657ca190f413f51c435b428f5a0789cd45df7e6161471a542667da
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137659);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3259");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt15163");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-info-disclose-9eJtycMB");
  script_xref(name:"IAVA", value:"2020-A-0205-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0042");

  script_name(english:"Cisco Adaptive Security Appliance Software Web Services Information Disclosure (cisco-sa-asaftd-info-disclose-9eJtycMB)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability exists in the web services interface of Cisco Adaptive Security Appliance (ASA) Software due to the
handling of parsing of invalid URLs. An unauthenticated, remote attacker can exploit this, by sending a crafted GET
request to the web services interface, in order to retrieve memory contents, which could lead to the disclosure of
confidential information.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-info-disclose-9eJtycMB
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ca70b7e2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt15163");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the Cisco Security Advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3259");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver': '9.6.4.41'},
  {'min_ver' : '9.7',  'fix_ver': '9.8.4.20'},
  {'min_ver' : '9.9',  'fix_ver': '9.9.2.67'},
  {'min_ver' : '9.10', 'fix_ver': '9.10.1.40'},
  {'min_ver' : '9.12', 'fix_ver': '9.12.3.9'},
  {'min_ver' : '9.13', 'fix_ver': '9.13.1.10'}
];

workarounds = make_list(
  CISCO_WORKAROUNDS['IKEv2_enabled'],
  CISCO_WORKAROUNDS['ssl_vpn']
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt15163',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
  