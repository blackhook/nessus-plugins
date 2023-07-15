#TRUSTED 3e934d3758aa2c6fd0c10e79c470e9305597658dcdd59342b1baaa5d46c48f44ae5cbab29bfb013794a5b00052a2de7f0f8215715e9dafbd133b20f3c573ef984974c64b10b1660cb8f1de6230271b3cb3d610811282a52b38701d5ee5e12f1d3a72f3510bf65d3bd3bcbae18e7240f718e1c9fac17e6ca72c2e6e59e9263f91e3035a47c0b64dbbab8efa3db1f5190561620a82670f1b1253c9e4c438ae66db04b9918cbdead31628b1b4fe710c6f28f4b63238d975e06431db47c57b228618b04f9d1242cb022aade524b5e8177e90a1176252d2a575f3e5f0314d9fa7daa2b14390ae390919c4a09cedd5c6d3bd899e9a9e98380f19248d312ffe48c428283cccc8caef9a9c3c8f8d5c7375347683bfed8bffd5da39188fb97909580c5bf0e4744ee9b13964b2587d9a0302705062d5929bd70f52044209f8fb3649f8d488eb95636d3624d11e8e9ffa56f20a52464a2f41ee6e6064d430b6e6c3d7df2a4cc88741c3454ff6f821adef3e3138926169e0a926620d527527635488d0b67b150bc6362641e47dd50b1dc2f39a1807a6db7db264932e2391d6c2baa44b27306dfe08b413896763fee437e4c4a19d95cb829a1672401e5d4c9f672469afaa0944f3f3e3f498d35484b160ada3c397955efed9ace52dbd0e4e5079f8c2b07fe3c0f3ed9ab16d07660a8ea5b0498dd92d2b489ca86c90e0b772aca14b7bd1b5be39
#TRUST-RSA-SHA256 91772c26bef33f788b39a0d29c88fb148ccd0ae7da27e3b23e60b1614fb9c33fcc4a1f60f2cd46e6cf4b3d94cafccba24188a53941138e264a671c6d97a4157e71d38cc6d3aa8f5ccbdbaa732d20fbf6592d6052e7d40eeca0db6e3aa09bd37639cb6ac6bc03cb6df986fe99ab5ec69331592afe991f17a77972eccd116dc488c431c538388474a5d3270191032ca0845cb0203ac255af417e595db8fa3a4ae639f204be90dba48c898eadf9acc9f6645794478e5ed0af9a79cfa6216167184c5d3bc74fb2987129fc51c4e313f8af3cda91e8d32577839855fcae0f298b0ae2f02e290b32eb168db7bde85b41f7b930a0ba16bd87e268781004580463a115b86791f9da4b59917a95dcf3e55f4bf6b29af9841c48fab720a96e209ecdcea11692b3204264b039a920ca362c6513d1666738ba7d7857feb4953f74721c9bed0e5f048e1bb53eab9676dce1ad2fc00036f93a7e3d5765bd0fc6420c0bf26da26b02c966ea37c195d54be254ee926640da78239ad571bbb2c323ab02d821ded82f10c654a2158aad424709a5581fb8123dca1001c13777a6123d739d405c6ae2011ff9c04e0336d9dc7cf4371991eb73aae11952975e5a4fbec59589177739ad1ec9fd3c78c0bf31d93f2001f4294c17f55d0e3f684d9df11369ad62b772a8188ca616a2dd44628e978ba250ddc8e59fe9b8c13cac325a9fbe3a8201b2bf79cf02
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108881);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2018-0167", "CVE-2018-0175");
  script_bugtraq_id(103564);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd73487");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd73664");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-lldp");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");

  script_name(english:"Cisco IOS XE Software Link Layer Discovery Protocol Buffer Overflow Vulnerabilities (cisco-sa-20180328-lldp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IOS XE is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-lldp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9b0c7a7a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd73487");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd73664");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvd73487 and CSCvd73664.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0167");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list = make_list(
  "3.10.8S",
  "3.10.9S",
  "3.10.10S",
  "15.3(3)S8a",
  "15.1(2)SNH",
  "15.1(2)SNI",
  "15.1(2)SNI1",
  "15.2(2)SNG",
  "15.4(1)T",
  "15.4(2)T",
  "15.4(1)T2",
  "15.4(1)T1",
  "15.4(1)T3",
  "15.4(2)T1",
  "15.4(2)T3",
  "15.4(2)T2",
  "15.4(1)T4",
  "15.4(2)T4",
  "15.2(2)JA",
  "15.2(2)JA1",
  "15.2(4)JA",
  "15.2(4)JA1",
  "15.0(2)EC",
  "15.0(2)EB",
  "3.5.0E",
  "3.6.0E",
  "3.5.1E",
  "3.7.0E",
  "3.5.2E",
  "3.5.3E",
  "3.6.1E",
  "15.2(4)E",
  "15.2(3)E1",
  "3.6.2E",
  "15.2(2a)E1",
  "3.6.3E",
  "15.2(2a)E2",
  "15.2(3)E2",
  "15.2(3a)E",
  "15.2(3)E3",
  "15.2(3m)E2",
  "3.7.1E",
  "3.6.4E",
  "15.2(2)E5",
  "3.7.2E",
  "15.2(4m)E1",
  "15.2(3)E4",
  "15.2(5)E",
  "3.7.3E",
  "15.2(2)E6",
  "15.2(5a)E",
  "15.2(5)E1",
  "15.2(5b)E",
  "15.2(4m)E3",
  "15.2(3m)E8",
  "15.2(2)E5a",
  "15.2(5c)E",
  "15.2(3)E5",
  "15.2(2)E5b",
  "15.2(4n)E2",
  "15.2(4o)E2",
  "15.2(5a)E1",
  "15.2(4)E4",
  "15.2(2)E7",
  "15.2(5)E2",
  "15.2(4p)E1",
  "15.2(6)E",
  "15.2(5)E2b",
  "15.2(4)E5",
  "15.2(5)E2c",
  "15.2(4m)E2",
  "15.2(4o)E3",
  "15.2(4q)E1",
  "15.2(6)E0a",
  "15.2(6)E0b",
  "15.2(2)E7b",
  "15.2(4)E5a",
  "15.1(3)MRA",
  "15.1(3)MRA1",
  "15.1(3)MRA2",
  "15.1(3)MRA3",
  "15.1(3)MRA4",
  "15.2(2)SNH1",
  "15.1(3)SVB1",
  "15.1(3)SVB2",
  "15.0(2)ED",
  "15.0(2)ED1",
  "15.2(2)JB",
  "15.2(2)JB2",
  "15.2(4)JB",
  "15.2(2)JB3",
  "15.2(4)JB1",
  "15.2(4)JB2",
  "15.2(4)JB3",
  "15.2(4)JB3a",
  "15.2(2)JB4",
  "15.2(4)JB4",
  "15.2(4)JB3h",
  "15.2(4)JB3b",
  "15.2(4)JB3s",
  "15.2(4)JB5h",
  "15.2(4)JB5",
  "15.2(4)JB5m",
  "15.2(4)JB6",
  "15.2(2)JB5",
  "15.2(2)JB6",
  "3.11.0S",
  "3.12.0S",
  "3.13.0S",
  "3.11.1S",
  "3.11.2S",
  "3.12.1S",
  "3.11.3S",
  "3.13.1S",
  "3.12.2S",
  "3.13.2S",
  "3.13.3S",
  "15.4(1)S4",
  "3.12.3S",
  "3.12.4S",
  "3.13.4S",
  "3.13.5S",
  "3.13.6S",
  "3.13.7S",
  "15.4(3)S6a",
  "15.3(3)JPB",
  "15.3(3)JPB1",
  "15.3(3)JD",
  "15.3(3)JD2",
  "15.3(3)JD3",
  "15.3(3)JD4",
  "15.3(3)JD5",
  "15.3(3)JD6",
  "15.3(3)JD7",
  "15.3(3)JD8",
  "15.3(3)JD9",
  "15.3(3)JD11",
  "15.6(3)M",
  "15.6(3)M1",
  "15.6(3)M0a",
  "15.6(3)M1b",
  "15.6(3)M2",
  "15.6(3)M2a",
  "15.1(3)SVJ2",
  "15.2(4)EC1",
  "15.2(4)EC2",
  "15.3(3)JPC",
  "15.3(3)JPC1",
  "15.3(3)JPC2",
  "15.3(3)JPC3",
  "15.3(3)JPC100",
  "15.3(3)JPC5",
  "15.3(3)JND",
  "15.3(3)JND1",
  "15.3(3)JND2",
  "15.3(3)JND3",
  "15.4(1)SY",
  "15.4(1)SY1",
  "15.4(1)SY2",
  "15.4(1)SY3",
  "15.3(3)JE",
  "15.3(3)JPD",
  "15.3(3)JDA7",
  "15.3(3)JDA8",
  "15.3(3)JDA9",
  "15.3(3)JDA11",
  "15.5(1)SY",
  "15.3(3)JF",
  "15.3(3)JF1",
  "15.3(3)JF2",
  "15.3(3)JCA7",
  "15.3(3)JCA8",
  "15.3(3)JCA9",
  "15.7(3)M0a"
);

workarounds = make_list(CISCO_WORKAROUNDS['show_lldp']);
workaround_params = make_list();


reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvd73487/CSCvd73664",
  'cmds'     , make_list("show lldp")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
