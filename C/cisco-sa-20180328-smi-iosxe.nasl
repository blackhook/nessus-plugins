#TRUSTED 3670c27379ca1300299ec2a5e0c669456085bd5fbfe664efa9008efacfc9569898eea6129d6d4c03b2546d0f1d43317542ece18d9494c16c64a2c1b409b7f6461a6183f2970c2a380c4c38bdf7b0eec2da5e04c235c3e18bf278d4a92f8a121beea93465efd201f46101eed1d44c753386c71b3ffedc97b92467552b380eeef38981ba03f13adf666abe6c0c5db7419ee257ffd855fb766723e69add5450b624b031bff6f3aa2defd34bb6b85c3dad11952d24659a3a8e6771850863647a56a664ec2d14df792042a4a4103b14941f6f877af96de658ae51030c4f808b6c259f0ad6532b049f47437f34e5b809439ce20ebef5b1162e0213514c9930992ded9f87d0e1f468ef39a2f792df5af5bf1cf9f5cf5785a79338949f915832388b852b8b6ce3a1b5f5364a25bf6f410277c69c51ed2b15749d366027260004d06dced622afea760c4a48ee82c4d9b3611cc4611b20177aaf6ca861aad375d9dc4ba6e4c95b8f7bc2150e7497ebb896e5793b2ce6c51219393b08427835a60a78367a2e4e6cd5bfc8452efebbb95e7b12bb5d9896186eeffa0112e8b928d8f44266447c0cc0fe27e6da7dbc55a2b6caa5cf01c358afe0a64d110c84f1c6d93f7c910115a7ac018de58dc43e0c7d3ca4deb24a8cce33f63f290efbd431baae2fa658e9b8e2a69119eea7735c748f308265e51f0301437625661e841f1f963cd1e2063144
#TRUST-RSA-SHA256 46d4e908035fae3da4f88f14d38880f06495a30eba0039c384b024c68dc54a3a93a2882cbe1262467dedf2f73a1c564b6adc13b3b3a904920e15b659569e735692f4b463ecfba79c3d0b9867925bd2821ac296010eddd604e7f887fbe6c4ac022532f47d723ddc76c781bca2656c8af5adb187d324490617307d120aa3bde38a120a5adee61ff8499dd74843c4f458feff7d8b7f7695a35037777f58cb79dcf1be983b205bbdb3ab6d252992328db6d483ba77e915e8259e168f6a2e4af6e49efbc600608231c3cceb2fecea1f8d9ad6c120f69253facf3344a2c2b7820ff645e82c39a96adfba4eed054dab96c9b74d3c1a2c7885477058b4d3ff5515727fb6f8cd88048990afaaae9c5473236d6f8d8e6db7f03776c63f87c7bf84bb59604189d72a20c7b1258df39d7c403a0cac588b9a4da82e2e8cbc6c4520b7efb3c24a8721cd909eaf06c22ec3f897ff485a5a16586552a20902864f81652ec3153227689c22e0fa6c66ca190716269e4b06222edb5c034a0f9b299a0fb9b32c9887b420aeff973d599f278bad78c588dfded7e3678ca87d47c46607fab9e8882d76b699eb8a9cc493b19b8dd4a6c9f06df66166c3e0d59c4532f72f59629a411f07094d15113b304f3d6acf153cb119e2d0f6930a6cc83bca2fdf125455c8ffca88844701e60280a80365bd8c11b80838e3e25a304e131ace5f0ff5f953bd54ca22dc
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131323);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2018-0156");
  script_bugtraq_id(103569);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd40673");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-smi");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");

  script_name(english:"Cisco IOS XE Software Smart Install DoS (cisco-sa-20180328-smi)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability
in the Smart Install feature due to improper validation of packet data. An unauthenticated, remote attacker can exploit
this by sending a crafted packet to an affected device on TCP port 4786 in order to cause the device to reload.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-smi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c08d6c6a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd40673");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvd40673.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0156");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list = make_list(
  '3.2.0SE',
  '3.2.1SE',
  '3.2.2SE',
  '3.2.3SE',
  '3.3.0SE',
  '3.3.1SE',
  '3.3.2SE',
  '3.3.3SE',
  '3.3.4SE',
  '3.3.5SE',
  '3.3.0XO',
  '3.3.1XO',
  '3.3.2XO',
  '3.4.0SG',
  '3.4.2SG',
  '3.4.1SG',
  '3.4.3SG',
  '3.4.4SG',
  '3.4.5SG',
  '3.4.6SG',
  '3.4.7SG',
  '3.4.8SG',
  '3.5.0E',
  '3.5.1E',
  '3.5.2E',
  '3.5.3E',
  '3.6.0E',
  '3.6.1E',
  '3.6.0aE',
  '3.6.0bE',
  '3.6.2aE',
  '3.6.2E',
  '3.6.3E',
  '3.6.4E',
  '3.6.5E',
  '3.6.6E',
  '3.6.5aE',
  '3.6.5bE',
  '3.6.7E',
  '3.6.7aE',
  '3.6.7bE',
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.7.4E',
  '3.7.5E',
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '3.2.0JA',
  '16.2.1',
  '16.2.2',
  '3.8.0E',
  '3.8.1E',
  '3.8.2E',
  '3.8.3E',
  '3.8.4E',
  '3.8.5E',
  '3.8.5aE',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.4.1',
  '16.5.1',
  '16.5.1a',
  '3.9.0E',
  '3.9.1E',
  '3.9.2E',
  '3.9.2bE',
  '16.6.1',
  '3.10.0E',
  '3.10.0cE'
);

workarounds = make_list(CISCO_WORKAROUNDS['smart_install_check']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvd40673',
  'cmds'     , make_list('show vstack config')
);

cisco::check_and_report(
    product_info:product_info,
    workarounds:workarounds,
    workaround_params:workaround_params,
    reporting:reporting,
    vuln_versions:version_list
);
