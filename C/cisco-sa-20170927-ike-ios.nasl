#TRUSTED 3964c61a11fc62b711605a79e56518840ee5aa664a72c6cd4305d5bd309aafead5936a58c21e4b3aed26fa3264c6f66138dae440f80890fa155d19853525e80cc3049614f784b7ae50d7552f8e5ff8b614d5172b0d986189d31ad577fbb54d34a858a0f37671b577a2562e7047407b0e8bd29199e29a68404ab993d235af9f86267a9c598dbeadca1e163835de624bfb564bab1c42f2b3a1eea316599610b1fa1ae73906bc95e547fd289fdc070add40ba1b9bdbeb2c40ee94b5dc635b92ba08821cdadbed0a3421c07882ec3a201dfbc0149360c352e314ef68402a189974155f5c52818f0cab58160480ce704994e81ce3756a4b03371aa33f580a3b30842c95c625246a58ac8388da6a5069ba27b70e7d159097799bd5ffdbed718af0baa04ccf88e257be479f151eb9ac6c85e439946689b68a7e7b24f606053ecc9ef3968049669807a44dac330ca756cccaed113c3c5bdbfd596d1b990970b1a70fa08dce4fcdc113cf08890c3951c03cc5d3a0808974c070c311cb369adb48eb67f1af2f2dd696ffda1e8e67dd435cdc5336112aafdc311b33e16fea294729f1ee31823e1ef8b26d66f571e216d69e9127f4f77e42b7d7e35c8c738bcda9e15e89789bf0121fbdd90fc24b3db4f7da5fe1bf5d0d5c2f3b4629c47706251b662b799a76fbeab94e46d33cb431d08edd2f514e0be61c106def0129c9168ef0b857e601fd
#TRUST-RSA-SHA256 b268cd102428a4e7c096b941111d30d488358a116e4d08581754cf11755a4524f4dcdad100bd6e1d2fbd0420004e1e9ef448ceeaae8470dd8aeba83ce604ae47a4f44ff6688078f431b16a1d95133fbf61bc641b872488a2267329ff7e4cbe5f846d3e358d3de226a4f278b1300d113294dd086362a10edd6b09810fb6ad8722dd5a25bd25bf1ef5077ecc9a6da781b2b15fb13b6ef5cb2c57356719b662099361b88c2f9059362aa1c8bc3be61252daa531fdf9a5ff75a41cfafb9df98b3075d295a2a0f26c0ef46b2ce8d6c453149cb738c454fb2bf027426340285531fdbaa1050c226dea6baa910e87340919ef683fd006f5c5435adc142b3f765cdab4aaad1ff010a0f58d8012bbf7ef93781a49eef54c80a28a47c92e4620a78eaedb1e6ac58fcd663708a9d529d527b3b326e3739ad5456286c3ad359bdfe2d2fa7d783494e504ffaef8e1ed8f2c6f55e2bbbd9bf11d00f97cb258a92648b1469a71f102122ad35824ed485decc6ae2cbe9c161a7d78b3d09a0f3d731cfb7571d7e48e66cddae0925dfef988faf93788d030771e16f04190c39f4f257e6d041bd7fe645f457762e891edb1d41a72f10e5e03efeca6427489e3e2dd3c4900061c64cd1fffaccfdabcfef9f40c7de8edbe166639c38647f79b1753b34355b3807eabb88198d2acfe805a44fdcd7e83b61cc9431001e2b9707d3c610f797bd280fa3fd9f7
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103693);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2017-12237");
  script_bugtraq_id(101037);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc41277");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170927-ike");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"Cisco IOS Software Internet Key Exchange Denial of Service Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IOS is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170927-ike
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e9f54a3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc41277");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvc41277.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12237");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS");

version_list = make_list(
  "15.0(2)EJ",
  "15.0(2)EJ1",
  "15.0(2)EX",
  "15.0(2)EX1",
  "15.0(2)EX3",
  "15.0(2)EX4",
  "15.0(2)EX5",
  "15.0(2)EZ",
  "15.0(2)SE1",
  "15.0(2)SE10",
  "15.0(2)SE10a",
  "15.0(2)SE11",
  "15.0(2)SE2",
  "15.0(2)SE3",
  "15.0(2)SE4",
  "15.0(2)SE5",
  "15.0(2)SE6",
  "15.0(2)SE7",
  "15.0(2)SE8",
  "15.0(2)SE9",
  "15.0(2)SQD7",
  "15.0(2a)EX5",
  "15.0(2a)SE9",
  "15.1(1)SY",
  "15.1(1)SY1",
  "15.1(1)SY2",
  "15.1(1)SY3",
  "15.1(1)SY4",
  "15.1(1)SY5",
  "15.1(1)SY6",
  "15.1(2)SG7a",
  "15.1(2)SY",
  "15.1(2)SY1",
  "15.1(2)SY10",
  "15.1(2)SY2",
  "15.1(2)SY3",
  "15.1(2)SY4",
  "15.1(2)SY4a",
  "15.1(2)SY5",
  "15.1(2)SY6",
  "15.1(2)SY7",
  "15.1(2)SY8",
  "15.1(2)SY9",
  "15.2(1)E",
  "15.2(1)E1",
  "15.2(1)E2",
  "15.2(1)E3",
  "15.2(1)EY",
  "15.2(1)SY",
  "15.2(1)SY0a",
  "15.2(1)SY1",
  "15.2(1)SY1a",
  "15.2(1)SY2",
  "15.2(1)SY3",
  "15.2(1)SY4",
  "15.2(2)E",
  "15.2(2)E1",
  "15.2(2)E2",
  "15.2(2)E3",
  "15.2(2)E4",
  "15.2(2)E5",
  "15.2(2)E5a",
  "15.2(2)E5b",
  "15.2(2)E6",
  "15.2(2)EB",
  "15.2(2)EB1",
  "15.2(2)EB2",
  "15.2(2)GC",
  "15.2(2)S",
  "15.2(2)S0a",
  "15.2(2)S0c",
  "15.2(2)S1",
  "15.2(2)S2",
  "15.2(2)SNG",
  "15.2(2)SNH1",
  "15.2(2)SNI",
  "15.2(2)SY",
  "15.2(2)SY1",
  "15.2(2)SY2",
  "15.2(2)SY3",
  "15.2(2)T",
  "15.2(2)T1",
  "15.2(2)T2",
  "15.2(2)T3",
  "15.2(2)T4",
  "15.2(2a)E1",
  "15.2(2a)E2",
  "15.2(3)E",
  "15.2(3)E1",
  "15.2(3)E2",
  "15.2(3)E3",
  "15.2(3)E4",
  "15.2(3)E5",
  "15.2(3)EX",
  "15.2(3)GC",
  "15.2(3)GC1",
  "15.2(3)T",
  "15.2(3)T1",
  "15.2(3)T2",
  "15.2(3)T3",
  "15.2(3)T4",
  "15.2(3a)E",
  "15.2(3a)E1",
  "15.2(3m)E2",
  "15.2(3m)E3",
  "15.2(3m)E6",
  "15.2(3m)E8",
  "15.2(4)E",
  "15.2(4)E1",
  "15.2(4)E2",
  "15.2(4)E3",
  "15.2(4)E4",
  "15.2(4)EC",
  "15.2(4)EC1",
  "15.2(4)EC2",
  "15.2(4)GC",
  "15.2(4)GC1",
  "15.2(4)GC2",
  "15.2(4)GC3",
  "15.2(4)M",
  "15.2(4)M1",
  "15.2(4)M10",
  "15.2(4)M11",
  "15.2(4)M2",
  "15.2(4)M3",
  "15.2(4)M4",
  "15.2(4)M5",
  "15.2(4)M6",
  "15.2(4)M6a",
  "15.2(4)M7",
  "15.2(4)M8",
  "15.2(4)M9",
  "15.2(4)S",
  "15.2(4)S1",
  "15.2(4)S2",
  "15.2(4)S3",
  "15.2(4)S3a",
  "15.2(4)S4",
  "15.2(4)S4a",
  "15.2(4)S5",
  "15.2(4)S6",
  "15.2(4)S7",
  "15.2(4m)E1",
  "15.2(4m)E3",
  "15.2(4n)E2",
  "15.2(4o)E2",
  "15.2(4p)E1",
  "15.2(5)E",
  "15.2(5)E1",
  "15.2(5)E2",
  "15.2(5)E2a",
  "15.2(5)E2b",
  "15.2(5)E2c",
  "15.2(5a)E",
  "15.2(5a)E1",
  "15.2(5b)E",
  "15.2(5c)E",
  "15.3(1)S",
  "15.3(1)S1",
  "15.3(1)S2",
  "15.3(1)SY",
  "15.3(1)SY1",
  "15.3(1)SY2",
  "15.3(1)T",
  "15.3(1)T1",
  "15.3(1)T2",
  "15.3(1)T3",
  "15.3(1)T4",
  "15.3(2)S",
  "15.3(2)S0a",
  "15.3(2)S1",
  "15.3(2)S2",
  "15.3(2)T",
  "15.3(2)T1",
  "15.3(2)T2",
  "15.3(2)T3",
  "15.3(2)T4",
  "15.3(3)JBB6a",
  "15.3(3)JC50",
  "15.3(3)JC51",
  "15.3(3)JC7",
  "15.3(3)JCA7",
  "15.3(3)JD7",
  "15.3(3)JDA3",
  "15.3(3)JE1",
  "15.3(3)JF1",
  "15.3(3)JNC4",
  "15.3(3)JND2",
  "15.3(3)JNP2",
  "15.3(3)JNP4",
  "15.3(3)JPB",
  "15.3(3)JPB2",
  "15.3(3)JPC3",
  "15.3(3)M",
  "15.3(3)M1",
  "15.3(3)M2",
  "15.3(3)M3",
  "15.3(3)M4",
  "15.3(3)M5",
  "15.3(3)M6",
  "15.3(3)M7",
  "15.3(3)M8",
  "15.3(3)M8a",
  "15.3(3)M9",
  "15.3(3)S",
  "15.3(3)S1",
  "15.3(3)S1a",
  "15.3(3)S2",
  "15.3(3)S3",
  "15.3(3)S4",
  "15.3(3)S5",
  "15.3(3)S6",
  "15.3(3)S7",
  "15.3(3)S8",
  "15.3(3)S8a",
  "15.3(3)S9",
  "15.4(1)CG",
  "15.4(1)CG1",
  "15.4(1)S",
  "15.4(1)S1",
  "15.4(1)S2",
  "15.4(1)S3",
  "15.4(1)S4",
  "15.4(1)SY",
  "15.4(1)SY1",
  "15.4(1)SY2",
  "15.4(1)T",
  "15.4(1)T1",
  "15.4(1)T2",
  "15.4(1)T3",
  "15.4(1)T4",
  "15.4(2)CG",
  "15.4(2)S",
  "15.4(2)S1",
  "15.4(2)S2",
  "15.4(2)S3",
  "15.4(2)S4",
  "15.4(2)T",
  "15.4(2)T1",
  "15.4(2)T2",
  "15.4(2)T3",
  "15.4(2)T4",
  "15.4(3)M",
  "15.4(3)M1",
  "15.4(3)M2",
  "15.4(3)M3",
  "15.4(3)M4",
  "15.4(3)M5",
  "15.4(3)M6",
  "15.4(3)M6a",
  "15.4(3)M7",
  "15.4(3)S",
  "15.4(3)S1",
  "15.4(3)S2",
  "15.4(3)S3",
  "15.4(3)S4",
  "15.4(3)S5",
  "15.4(3)S5a",
  "15.4(3)S6",
  "15.4(3)S6a",
  "15.4(3)S6b",
  "15.4(3)S7",
  "15.4(3)S7a",
  "15.5(1)S",
  "15.5(1)S1",
  "15.5(1)S2",
  "15.5(1)S3",
  "15.5(1)S4",
  "15.5(1)SY",
  "15.5(1)SY1",
  "15.5(1)T",
  "15.5(1)T1",
  "15.5(1)T2",
  "15.5(1)T3",
  "15.5(1)T4",
  "15.5(2)S",
  "15.5(2)S1",
  "15.5(2)S2",
  "15.5(2)S3",
  "15.5(2)S4",
  "15.5(2)T",
  "15.5(2)T1",
  "15.5(2)T2",
  "15.5(2)T3",
  "15.5(2)T4",
  "15.5(3)M",
  "15.5(3)M0a",
  "15.5(3)M1",
  "15.5(3)M2",
  "15.5(3)M3",
  "15.5(3)M4",
  "15.5(3)M4a",
  "15.5(3)M5",
  "15.5(3)S",
  "15.5(3)S0a",
  "15.5(3)S1",
  "15.5(3)S1a",
  "15.5(3)S2",
  "15.5(3)S2a",
  "15.5(3)S2b",
  "15.5(3)S3",
  "15.5(3)S3a",
  "15.5(3)S4",
  "15.5(3)S4a",
  "15.5(3)S4b",
  "15.5(3)S4d",
  "15.5(3)S5",
  "15.5(3)SN",
  "15.6(1)S",
  "15.6(1)S1",
  "15.6(1)S1a",
  "15.6(1)S2",
  "15.6(1)S3",
  "15.6(1)T",
  "15.6(1)T0a",
  "15.6(1)T1",
  "15.6(1)T2",
  "15.6(1)T3",
  "15.6(2)S",
  "15.6(2)S0a",
  "15.6(2)S1",
  "15.6(2)S2",
  "15.6(2)S3",
  "15.6(2)SN",
  "15.6(2)SP",
  "15.6(2)SP1",
  "15.6(2)SP1b",
  "15.6(2)SP1c",
  "15.6(2)SP2",
  "15.6(2)SP2a",
  "15.6(2)T",
  "15.6(2)T1",
  "15.6(2)T2",
  "15.6(3)M",
  "15.6(3)M0a",
  "15.6(3)M1",
  "15.6(3)M1b",
  "15.6(3)M2",
  "15.6(3)M2a"
);

workarounds = make_list(CISCO_WORKAROUNDS['show_udp_ike'],CISCO_WORKAROUNDS['show_ip_sock_ike']);
workaround_params = {"check_queue_limit" : 1};


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvc41277",
  'cmds'     , make_list("show udp", "show ip sockets")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list, router_only:TRUE);
