#TRUSTED 5019fecb4a6d5497a56b20f1624c3fa095879b28e76b1d20cb4de58369921a0c523256b7c575f01372aea4a270a544eb0a39d0dfedab17d3df74bc5d813ddc8f79e4cd0986171cd5fc45f8d0430c643f17db229da2433575331ea93ea42bed6ccfe56c13c34765ee3df1336d8ced6de8ce2792d28620f135157a53f23d4b24bfc14be90177d06ff5e00051e113cdb2d9f74e663d4a8cf5a598b7837c8f09a106a58ac028bf66d1e61202cf6ef239c974f85d10af0ae9d6fb930f7d6bb60c57a70d0d482886f2942887ea59f57d9538c32d68316d04c44a5b13be549d15cbf75beece25a9ff34767206c1b0b1bf4f680e4d20547d9d1c19029122fa8b8be872c80a81a55d69ce0dd5966acb450cf97f9991a969907f20aec4912623d6e1ccb503dc7b2b0a586e08b1078e1f0f8530a5e60720cc633ba30350309b6471cbe6593922d689d647ad6878e83248cd13807d14ae577c2bf5a434ac0d38cfbc49c16f2b546a1a3541b773441851809987acf110bc10b2b4d33a988fdf7cff8c2c2cb4d010afaa7c1a489cce95287783b2db8042829b1a46c3a01477f93a3fd67d3895d635c181b8b2c154f9ce9eb2da9abae078e0f352e02e11f0a2eba36304b0b632319e736918ae1980112708af2d3df116c6754cf6de4d652e34f2e105526f22d3b3fed7964dc7f3f3d85bb03a64a9f79bfb65cf8bdd8d5969e9cb220fd1c20104c1
#TRUST-RSA-SHA256 96d2ee10a47866d3e6b46c4ebdc4c6af5bb1ed058b2f108cc70afb65ec2edb6a68e67b19f5b7f86eb51998e7fe9a6347269eefcbf7a0f0c4eaef3132e683c56f0becd2a652dd8ea62b475e6fa4b7281763dac3e53e1049cf7d0476f8d2ad76d45770341a561de78d6a62f0f02f59de08ab98d4d124750f231e1095e221945d7478fb42a24c3d28a07822c162cd4148cedd9e846c24e53efafa95da2ad21ca990edf576bed80a96ad2890d2efa41859db437427990f702cc61c26fdc329aacdc96736bd9cf48a34a027aad3d439945341eaf4fbafc92ba7e7d982d58983f212dfb44978346b1c5ce24e9d957650fb1ed27c2ec3104f181330086a99d920273e9688c8c73ea84eb6fcf1de8e34cf1b744aacfd58abeb8cab024005809c2f3594eaf3ee9f684b3c8dc7c7f63e4cf55d5baf9d4db7cca3b3638970ec24de1e247b489c143be67eddd6de80e21896258e5dba1084c9542adb42940df2925c6074a7153164a3ca3ae218665041da5dd366acda98e6334b0dbf7a43f9209fc24b780524af2e1ad80783996c253e13733856bbe22b3311efbd014a2468756aeff4ccd2308bd59adabf33cbdb9287f0972afaab78f38eee882d8e331a720e6f8cc374b6ea3a130dec902fcec41f7cc52599fe98b99c6db6e30b66ff646b6c9902b190a13fe47ca22d8369b8820c804a1fa0dcf1ac19387c38f425569f5c113623f03ade91
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136700);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3186");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr13823");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-accesslist-bypass-5dZs5qZp");
  script_xref(name:"IAVA", value:"2020-A-0205-S");

  script_name(english:"Cisco Firepower Threat Defense Software Management Access List Bypass Vulnerability (cisco-sa-ftd-accesslist-bypass-5dZs5qZp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its version and configuration, the Cisco Firepower Threat Defense (FTD) Software
running on the remote device is affected by vulnerability, where an unauthenticated attacker could bypass a configured
management interface access list on an affected system. The vulnerability is due to the configuration of different 
management access lists, one with ports allowed and denied in another. An attacker could exploit this vulnerability 
by sending crafted remote management traffic to the local IP address of an affected system. A successful exploit could 
allow the attacker to bypass the configured management access list policies, and traffic to the management interface 
would not be properly denied.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-accesslist-bypass-5dZs5qZp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?122de846");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr13823");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr13823");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3186");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_asa_firepower_version.nasl", "cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

vuln_ranges = [
  {'min_ver' : '6.3.0', 'fix_ver' : '6.3.0.6'},
  {'min_ver' : '6.4.0', 'fix_ver' : '6.4.0.7'},
  {'min_ver' : '6.5.0', 'fix_ver' : '6.5.0.2'}
];
workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr13823',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
