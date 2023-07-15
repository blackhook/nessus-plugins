#TRUSTED 34029a56a9536626e07786a50d06a3c50fe2b8ae4ce547eca47e551ab29f983c35d637277b99b3751ecee143083626cb744b5c8d1a8a0b3f11f28c8998bf872d27520c0cd82a3c2372f9cf7c28980a02884cb6b51acb5bb702879f6bc061c21d3f4d5cbd41bc13c4330439a5dcc15c763fd0fdd618fe9a6580f4a5cfa8574f07ac80f31b54ac84809c7c4cd9c51a43cf84603b4453b9d7cb75e0b3d2daca0997eee094543b179145666d1ac05446c8d97a2379276794c9b46e006ad9f2ec8ded2a7e7963ff05f83bd805ea7e6f3a28a80e495e93e6b08b35b99195b12c9118c36f139b0bb5bd8ef996786f3f0931c7fb5a998697ae666388b8f06af74a4f58aca69663ebd1c3d62e71efb9a8402f6d1c9ffb9106f3880ac8c5cbd1c2e9696ee496eb77ec16535c9f2b152e950e9579cab70b63d21f9be8e52e1588285325344ba42446dfb4cebc85c41501e61987e6a84bbc11fcb5ba553d2d0dd0a3405771b34886678a1e44097f960ae4e9a06d3faa25e7618eda3081d96b7999bdbf0d29340f67952809cd32b11990045d74df3c888be733ddf9429ace4b2b73407592915f727f76771ae303c47e9168ed1fe3bafcc5730dc710b6bdcfaad419da211fb708c52230b70f2684c9e16df58f4b645d703b580f1da145d74ca74296cb75e654abea8d9bdd47dad18135dde204a6dec42d6c807052d489dc721fd53e459f0f312c
#TRUST-RSA-SHA256 21dd84983757543876a932ad5c7d0bdef494cf900aa102378a8240c2cdc23768110a93a1298fe731cbb39eaab5ddf0ac87892d951558ec3c607ebe58660597e91b9e364a3a39beaf694198d4a44e99466e0011025e77501a6e02761bd8909d560bf16dbd52267e478d1178332ccd4cb5dfcb8efc6a4b175f31c9c235f2528e55f6c1f9bb1a8d2edc9a53f0ead0be4267c4e05e04ba624a26756ce6ccb6f0c48a9476362070aabccd0f5bb25766b6e033de0b6dc5465ad2fa10592e2b2b678b24135236942eab4899c755f0a26c3c6c839d15c19c5d58976cf1e49cd1a50c17689608e5327c9f0ad3a65f50fde0c6d7a92f8d23ccb1c224bca56f726d3915315c223e0a088c76ae9d326ef670d399982574542e14c9c29bcc8468e356cccc5bb232e91f8020ae3739fc5f4955c517a04e4f94af706436fee717a689f9d3c6f44d3797791dabf909d09199910f0785487c78f81aa5e593be27fd4bfca8074084d5e586cdac5a5699311e9639ca1fed075d8d3d535650877a002effcd4e4858a8ed289728036ab920db8a4ff8ce4b481abef5d7f60f3d420967166ea469d0ca9d836efb7625b0f707c267ac8b7c61e89828fe18658ed8bbb7cc4d44b46f67683c9360f9fdec43c4cd7e1b805ed216ae2d5439f1ddcbd19304ee8e87c2c7e8ba42cf92b65b021816c857fe7cd1870208343705035cf0603fce945be6ac8a4e01307a
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103670);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2017-12235");
  script_bugtraq_id(101043);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz47179");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170927-profinet");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"Cisco IOS Software PROFINET denial of service (cisco-sa-20170927-profinet)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
IOS software running on the remote device is affected by a denial of
service vulnerability in the PROFINET Discovery and Configuration
Protocol (PN-DCP) feature. An unauthenticated, remote attacker can
exploit this, via specially crafted PN-DCP requests, to cause the
switch to stop processing traffic, requiring a device restart to
regain functionality.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170927-profinet
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9b66383b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuz47179.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12235");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/05");

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
  '12.2(55)SE',
  '15.0(1)EY',
  '12.2(55)SE3',
  '12.2(52)SE',
  '12.2(58)SE',
  '12.2(52)SE1',
  '15.0(2)SE',
  '12.2(58)SE1',
  '12.2(55)SE4',
  '12.2(58)SE2',
  '12.2(55)SE5',
  '12.2(55)SE6',
  '15.0(2)SE1',
  '15.0(1)EY1',
  '15.0(2)SE2',
  '15.0(2)EC',
  '15.0(2)EB',
  '12.2(55)SE7',
  '15.2(2)E',
  '15.0(1)EY2',
  '15.0(2)EY',
  '15.0(2)SE3',
  '15.0(2)EY1',
  '15.0(2)SE4',
  '15.2(1)EY',
  '15.0(2)SE5',
  '15.0(2)EY2',
  '12.2(55)SE9',
  '15.0(2)EA1',
  '15.0(2)EY3',
  '15.0(2)SE6',
  '15.2(2)EB',
  '15.2(1)EY1',
  '12.4(25e)JAO3a',
  '12.4(25e)JAO20s',
  '12.2(55)SE10',
  '15.3(3)JN',
  '15.2(2)E1',
  '15.1(4)M11',
  '15.0(2)SE7',
  '15.2(2b)E',
  '15.2(3)E1',
  '15.2(2)E2',
  '15.3(3)SA',
  '15.2(2)E3',
  '12.4(25e)JAP3',
  '12.4(25e)JAO5m',
  '15.0(2)SE8',
  '15.0(2)SE9',
  '15.1(4)M12',
  '15.2(2a)E2',
  '15.2(3)E2',
  '15.2(2)EA1',
  '15.2(2)EA2',
  '15.2(3)EA',
  '15.2(3)EA1',
  '15.2(1)EY2',
  '15.2(2)JA3',
  '15.2(4)JB8',
  '15.3(3)JAX3',
  '15.3(3)JN5',
  '15.4(3)SN2',
  '15.5(2)SN0a',
  '15.2(3)E3',
  '15.2(2)EB1',
  '15.5(3)SN1',
  '15.3(3)JN6',
  '15.3(3)JBB3',
  '15.2(4)EA',
  '12.2(55)SE11',
  '15.2(2)E4',
  '15.2(4)EA1',
  '15.2(2)E5',
  '12.4(25e)JAP1n',
  '15.3(3)JBB7',
  '15.3(3)JC30',
  '15.2(3)E2a',
  '15.5(3)S2a',
  '15.3(3)JBB6a',
  '15.0(2)SE10',
  '15.2(3)EX',
  '15.3(3)JPB',
  '15.2(3)E4',
  '15.2(2)EA3',
  '15.2(2)EB2',
  '15.3(3)JNP2',
  '15.6(2)S0a',
  '15.2(4)EA3',
  '15.4(3)S5a',
  '15.5(3)S2b',
  '15.6(1)S1a',
  '12.4(25e)JAP9',
  '15.2(4)EC',
  '15.1(2)SG7a',
  '15.5(3)S3a',
  '15.3(3)JC50',
  '15.3(3)JC51',
  '15.6(2)S2',
  '15.3(3)JN10',
  '15.2(4)EB',
  '15.2(2)E6',
  '15.2(4)EA4',
  '15.2(4)EA2',
  '15.3(3)JPB2',
  '15.5(3)S4a',
  '15.2(2)E5a',
  '15.5(3)S4b',
  '15.2(3)E5',
  '15.0(2)SE10a',
  '15.2(4)EA5',
  '15.2(2)E5b',
  '15.2(5a)E1',
  '15.6(2)SP1b',
  '15.5(3)S4d',
  '15.6(2)SP1c',
  '15.2(4a)EA5',
  '15.5(3)S4e',
  '15.1(2)SG9',
  '15.3(3)JPC3',
  '15.3(3)JDA3',
  '15.5(3)S5a',
  '15.4(3)S6b',
  '15.4(3)S7a',
  '15.3(3)JNC4',
  '15.4(3)M7a',
  '15.5(3)S5b',
  '15.6(2)S3',
  '15.3(3)JC7',
  '15.6(2)SP2a',
  '15.3(3)JND2',
  '15.3(3)JCA7',
  '15.0(2)SQD7',
  '15.2(5)E2a',
  '15.2(5)E2b',
  '15.3(3)JE1',
  '15.3(3)JN12'
);

workarounds = make_list(CISCO_WORKAROUNDS['profinet']);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCuz47179',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, reporting:reporting, vuln_versions:version_list);
