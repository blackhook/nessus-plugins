#TRUSTED 971c0f5f3e2bd5fc9230dd32b126875050af7d5472f782057333ba2eb4a9d40b34a12de518495956dffbca3e2a42663b88f458c7cb1cb62850828c3a1dfdb3558241a21b5467e208d2881916bef576d21e7420822ce7d7bcca8775098f63c5df926541870737894da51af069064b32724f726810e3d045d3718ee9d7f3289ade24e4443fb0f43e727b82de0a166894aae9932c53c922dbc89242ee8f37c4735af986f93a0eedbeb1657da60c7ff5d2fd9a4ad89ac5dc71e94ae1a62194b7c7d25c5837eecd6e08f484e9d2c80261ea7fe80f0e448979a9335c45cfb59b3eee57b98ceb7ac1989d9b640eba19e01f6705d99b2c4dbf0cc7fde8b079028e6bedc6ada39bf32767fa545fd9dd845d9a3ab26f90cccf504cce336b706f3f8e363d450137dd96d7959825a5a36db160b0187f2f5968fa2dba11c8b69258712c83bb92e693ce9c7d37d7ad395db7881cc95f4cf6b50bcab8d2df488360b1a222edf34cfab7ab5784c11fc3b30820d6f7506c0a31bbdcc6b11717ce4c7f745b5512a60dc2ad9537823bdfa6651d74dffaa2fe5ea6b0e9025a81c6f3c013469cf37032d564dc3e22e0faa6db85818bf21cf7d08941ebfc4c48cada48c09003e968b2e3a8cc1c1dc1a0a91f4f9a46e5e299a7a188b5d0fab8439809bfc76b7c0dc0d8f33d1612f13ed78acffc64f2e54db77f9c2817fd9d3a8c5b3811b61db6726e3f2ef5
#TRUST-RSA-SHA256 0e10abf7fdd9481d0048e9d766fcccddbdee48e2508527966edc3acfb71f3c1187ba115d654e0772bb407167adc04fa6df048ea917983c38037d1eedf6f135ad10f4daf6bde4688c796681431e4c73bc93053a1f952faa8e12cda1375ec8673e272ce8fb5b9ba9c7d26c9941c1b4b4f4a1118deba272e2ec9f7f47c45a30aa6ecd38f3cde439af7c6cfe47206602e24e1670a5a696c3829f056ae1fca3e32fce3edba4c62a91640f0c6f4f8ab9f4dd50399a022a1f8ecdc7f0f719c2317f7074cce63318b98ab1acd63290b2fd997066651325d34e73effaf9f2e98032cda62b507d8e2f0822bb028d657e58ab57ae70fe3a5c9933f54331b59dceb738556e805ab732b3770246555d668167e278110eb703f96214df9fadb345a9e110c68079b7cef4c23dcc95a5053dea75260ada4a82cee2fc2dc2fbba60cb3f497f2b31e27110556ce18d42fc703af0ce975c9abd67eefd40224d2d547ac940bd1387ccaca2e9608174725bbb9b058caca0e3aa0b8be108b4a5c9312721fd14d5998bc638c62b5bcd031987de9f3ca93302782d2033e4ce881db19711888c24ebe2034fe704599d126427b126f5fcbe4f5f313cea1ec0828c8b0af1ec46c80120a4d5de1395b3304d78153326b933d57c80a7542f02ede3e2ce15be0068441af5a59dbbf90b1bedb7ce3196764cab9e8c4d4302f042117aab49eb8d42b9f716b3c60d7716
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103669);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2017-12231");
  script_bugtraq_id(101039);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc57217");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170927-nat");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"Cisco IOS Software NAT denial of service (cisco-sa-20170927-nat)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
IOS software running on the remote device is affected by a denial of
service vulnerability in the Network Address Translation (NAT)
feature. An unauthenticated, remote attacker can exploit this, via
specially crafted NAT requests, to cause the switch to stop processing
traffic, requiring a device restart to regain functionality.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170927-nat
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7014611");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvc57217");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12231");

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
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

vuln_versions = make_list(
  '15.2(4)M8',
  '15.2(4)M10',
  '15.2(4)M9',
  '15.3(3)S6',
  '15.2(1)EY1',
  '12.4(25e)JAO3a',
  '12.4(25e)JAO20s',
  '15.3(3)M6',
  '15.5(2)S',
  '15.3(3)JN',
  '15.5(3)M',
  '15.1(4)M11',
  '15.4(1)T4',
  '15.6(1)S',
  '15.5(3)S',
  '15.3(3)SA',
  '15.6(1)T',
  '15.5(2)T',
  '15.4(3)S3',
  '15.2(2)E3',
  '15.4(3)M3',
  '12.4(25e)JAP3',
  '12.4(25e)JAO5m',
  '15.1(4)M12',
  '15.2(3)EA1',
  '15.2(1)EY2',
  '15.2(2)JA3',
  '15.2(4)JB8',
  '15.2(4)S7',
  '15.3(3)JAX3',
  '15.3(3)JN5',
  '15.3(3)M7',
  '15.3(3)S7',
  '15.4(3)M4',
  '15.4(1)S4',
  '15.4(2)S4',
  '15.4(3)S4',
  '15.4(3)SN2',
  '15.4(2)T4',
  '15.5(1)S2',
  '15.5(1)S3',
  '15.5(2)S1',
  '15.5(2)S2',
  '15.5(2)SN0a',
  '15.5(1)T2',
  '15.5(1)T3',
  '15.5(2)T1',
  '15.5(2)T2',
  '15.6(2)S',
  '15.6(2)T',
  '15.3(3)S8',
  '15.5(3)M1',
  '15.3(3)M8',
  '15.5(3)SN1',
  '15.3(3)JN6',
  '15.5(3)M0a',
  '15.3(3)JBB3',
  '15.5(3)S1',
  '15.2(4)S8',
  '15.2(4)M11',
  '15.4(3)S5',
  '15.5(2)T3',
  '15.5(3)S1a',
  '15.4(3)M5',
  '15.5(2)S3',
  '15.5(3)M2',
  '15.6(2)S1',
  '12.4(25e)JAP1n',
  '15.6(1)T0a',
  '15.5(3)S2',
  '15.3(3)JBB7',
  '15.6(2)SP',
  '15.6(1)S1',
  '15.3(3)JC30',
  '15.6(1)T1',
  '15.2(3)E2a',
  '15.5(3)S0a',
  '15.5(2)XB',
  '15.3(3)S6a',
  '15.3(3)S9',
  '15.5(3)S3',
  '15.5(3)M2a',
  '15.5(3)S2a',
  '15.3(3)JBB6a',
  '15.5(3)M3',
  '15.2(3)EX',
  '15.4(3)S6',
  '15.5(2)T4',
  '15.3(3)JPB',
  '15.6(3)M',
  '15.6(1)S2',
  '15.4(3)M6',
  '15.5(1)S4',
  '15.5(1)T4',
  '15.3(3)JNP2',
  '15.6(2)S0a',
  '15.6(2)T1',
  '15.4(3)S5a',
  '15.5(3)S2b',
  '15.6(1)S1a',
  '15.6(1)T2',
  '15.6(2)T0a',
  '12.4(25e)JAP9',
  '15.2(4)EC',
  '15.5(2)S4',
  '15.1(2)SG7a',
  '15.5(3)S3a',
  '15.3(3)JC50',
  '15.3(3)JC51',
  '15.6(2)S2',
  '15.6(2)T2',
  '15.3(3)JN10',
  '15.2(4)EB',
  '15.5(3)M4',
  '15.5(3)S4',
  '15.6(3)M1',
  '15.4(3)S7',
  '15.6(2)SP1',
  '15.6(3)M0a',
  '15.1(4)M12a',
  '15.3(3)M8a',
  '15.3(3)S8a',
  '15.4(3)M6a',
  '15.4(3)S6a',
  '15.3(3)JPB2',
  '15.5(3)S4a',
  '15.5(3)M4a',
  '15.5(3)S4b',
  '15.2(2)E5b',
  '15.6(1)S3',
  '15.5(3)M4b',
  '15.5(3)S5',
  '15.2(5a)E1',
  '15.5(3)M4c',
  '15.6(2)SP1b',
  '15.5(3)S4d',
  '15.6(3)M1a',
  '15.6(2)SP1c',
  '15.6(3)M1b',
  '15.6(2)SP2',
  '15.2(4a)EA5',
  '15.5(3)S4e',
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
  '15.3(3)JNP4',
  '15.2(5)E2a',
  '15.2(5)E2b',
  '15.3(3)JE1',
  '15.3(3)JN12',
  '15.6(2)S4',
  '15.3(3)JD7',
  '15.3(3)JF1'
);

# Check for vuln version
foreach version (vuln_versions)
{
  if (version == ver)
  {
    flag++;
    break;
  }
}

# Check that NAT is enabled
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_run_|_include_ip_nat",
                              "show run | include ip nat");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"ip nat", string:buf))
    {
      # we also need to check if NAT ALG is enabled for H.323 RAS messages
      buf = cisco_command_kb_item("Host/Cisco/Config/show_run_|_include_ip_nat_service_ras",
                                  "show run | include ip nat service ras");
      if (!preg(multiline:TRUE, pattern:"no ip nat service ras", string:buf))
        flag++;
    }
  }
  else if (cisco_needs_enable(buf))
  {
    flag++;
    override++;
  }
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : ver,
    bug_id   : 'CSCvc57217',
    cmds     : make_list('show running-config', 'show run | include ip nat', 'show run | include ip nat service ras')
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS software", ver);
