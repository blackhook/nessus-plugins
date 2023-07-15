#TRUSTED a35e3598653634830760f3b4071f6571d9199dff8929fdd892fd72410743c46404d7ca27413d1260ca04b84f86308968e57449c716c18547759ac1031d4b40fc2f0bb6367bc343223c313eabfc3fcee9d2fe1eda81cd4da9ec35226ddc2a4e45866ea23fccb5278c0565d11fd83671c9238d4718f3c2d075474a27047871df6de7d2c745bbc1169a932c3523174404647589334d16773e15fe72da39a310d38f6a0ed3dc6d8466f24b2992c120716fe8106d351e05771d53cfc99a547d4b689b461e028bc4b603b0d022917b59c31ce77e19a7f299983fd49c73b20146cb072342f6672b249cfa86c87e431a418d9f426f9a4c0feb7f3b639cfa9931c6fb982c1b985c6b501c00e16b769ecb4a9a64eca955491aef40907239329169683a3e5412fca47e5df7688e24f343a779286cbe72237a787c9fbe2a0998d05f1a6d481f89b24aff2b64cb52b9807c38258c8b6c98a054130d4f70cf65697d72fb22b1a88608d515fe6e08db98c7ab0b1654dd31916d4e20dbd7b0f763c70e24336f1ebd613845208c665899f80728b043b2e6db7a4349cb2d5a8913461c89dc04bf228fadf14c2ac96e2bd7f9e4a15aa1f8601335c485512981bc6c578a12e9d65532d759e98538faaeeaa74c068902d4c86aa7bd949b79c5e171eb651f29af0aed97dcf8062a6f619066d80eda4a485c4905b37066c63cddd42294916548cf38a96335
#TRUST-RSA-SHA256 7d9686dfcf69310ec04f317b4d20a524823b41828dca24041dc446d35cd3cb25ed04276fa0cbc0d38e37da85beb24968529ce1f0d6e622caa4f6e76ecc8d023fe6f224ca193cc566079df66f1ebacd842d86d7d567cf18f61e5ddd9d25911d6040cfcef220d327c4f6246918a7b4b6daec0c6cca025ed204338d17add882b85a402ae94aef24e7ecd488991e7318d8b9e4d2b8934d6bed8001eea5e7bf641de3569904a4879e1de96cb2a15c13acbf56bd11c5662c09d8fc8bafcc2f2f7f804332f5a0757341fb824a42ff66e39b44efe25c6f3bbce2fa3bce45014b5bbb21174d54be583cbf13fdde3fce660cf7be7a09cbe8d88072991ffb2fe8e1ef2dc299916c8c7974a9d4fbdd0fe36b8980e682174319f905fe23afe080bd960330e0ac08aa6c1ee760bf6ef7f4b60da9530a57dcf613fe1a64777d86a825cc62ca33263eb122bed33186ff844d4f283c9facb3cdd359840e7b3b8ca30d66d95f8f1a7b70268aea61c0dddf9f2780c739f1586736d3c274c2be906190e8baf31491f0078532b4b7a84a1411a3c82255f6c8288b6647765b7a8b186b214adaed59f9677ed8832b3079c8bb90bfdf38cfc2f92c6e5db586acb15dbbf207b175cf0e83228cb70a793d56c8824807af93101e3d5e01d7f22938e3bb946d60e83755ea3cec79ec90502994efb85bec83a2dbbe0e7b64c9f9b0ebc13a16c1ff3dd25941868643
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108720);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2018-0151");
  script_bugtraq_id(103540);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf73881");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-qos");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");

  script_name(english:"Cisco IOS Software Quality of Service Remote Code Execution Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IOS is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-qos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10160b36");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf73881");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvf73881.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0151");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS");

version_list = make_list(
  "15.2(2)E5b",
  "15.2(5a)E1",
  "15.2(6)E0b",
  "15.5(1)S",
  "15.5(2)S",
  "15.5(1)S1",
  "15.5(3)S",
  "15.5(1)S2",
  "15.5(1)S3",
  "15.5(2)S1",
  "15.5(2)S2",
  "15.5(3)S1",
  "15.5(3)S1a",
  "15.5(2)S3",
  "15.5(3)S2",
  "15.5(3)S0a",
  "15.5(3)S3",
  "15.5(1)S4",
  "15.5(2)S4",
  "15.5(3)S4",
  "15.5(3)S5",
  "15.5(3)S6",
  "15.5(3)S6a",
  "15.5(3)S6b",
  "15.5(1)T",
  "15.5(2)T",
  "15.5(1)T3",
  "15.5(2)T1",
  "15.5(2)T2",
  "15.5(2)T3",
  "15.5(2)T4",
  "15.5(1)T4",
  "15.5(3)M",
  "15.5(3)M1",
  "15.5(3)M0a",
  "15.5(3)M2",
  "15.5(3)M3",
  "15.5(3)M4",
  "15.5(3)M4a",
  "15.5(3)M5",
  "15.5(3)M6",
  "15.5(3)M6a",
  "15.5(3)SN",
  "15.6(1)S",
  "15.6(2)S",
  "15.6(2)S1",
  "15.6(1)S1",
  "15.6(1)S2",
  "15.6(2)S0a",
  "15.6(2)S2",
  "15.6(1)S3",
  "15.6(2)S3",
  "15.6(1)S4",
  "15.6(2)S4",
  "15.6(1)T",
  "15.6(2)T",
  "15.6(1)T0a",
  "15.6(1)T1",
  "15.6(2)T1",
  "15.6(1)T2",
  "15.6(2)T2",
  "15.6(1)T3",
  "15.6(2)T3",
  "15.3(1)SY3",
  "15.6(2)SP",
  "15.6(2)SP1",
  "15.6(2)SP2",
  "15.6(2)SP3",
  "15.6(2)SN",
  "15.3(3)JD8",
  "15.6(3)M",
  "15.6(3)M1",
  "15.6(3)M0a",
  "15.6(3)M1b",
  "15.6(3)M2",
  "15.6(3)M2a",
  "15.6(3)M3",
  "15.6(3)M3a",
  "15.3(3)JDA8",
  "15.3(3)JF2",
  "15.7(3)M",
  "15.7(3)M0a"
  );

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['show_udp_dmvpn'];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvf73881",
  'cmds'     , make_list('show udp')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_versions:version_list
);
