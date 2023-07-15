#TRUSTED 5ae4915410c3bed0af7f781a8330decc1d813f5f4588f0b25c31fa56aae6e05f001a2ebb74b30d2ec5ee8ece60d6277d8a3175ea609225f08c077cd55aa33b6f144d050420748d077abd0364e4209d9032b767343ee7b8146c9dc3f93ce6412cbd18f0b037fb79090ee40ecd373182857deed0455d0557c7336aca7d9b67a72287b9f172f5ae909c028dccb0efdcc99099f3bdeffda795a8e06afb7fc7d1f75495dc82c85deea99a81943741b3d80e8d2a05944b32eba63f234e22e3245ba3a0e18dbf680a84e8054b37488029146e0d43863710fae9e491239ff0241fec0623990f0b82f9ab7ae7ebcb9c0e7fca6e63ca6444e8683484cd3c939a11e291eb7c6d73d4efe644980e7a41d8a36edc3b8d48cb4c985c9f251e262e8dc478f6247617c8d5d8bb29b74a590fb751b37a7773f07216873fe329bcab38fabd7f4cee08a004265d3b3c71816b533ee974ac5ffa010ad75ac0f2b671fcb49745c00633561a7bfc93c189ac9b0dc14740c8c9ff248263444635f5eeb316010fcf61713cba4b57e7ea1c892b065753c5e5c800f5ae53bd99cec4b8d8514d6e9c78956534f349188c5b12ce7241af116e2d56f74ec2952bd70a658bccdc26bfdd5f25d3f54b43a672a76be8cce0edec6703fe5bdd3e86ed7dbc7a73c251ce05f045d2a55352abda19540964bb6b051682b41f6b400a2cbc334a8f33ce2aedb28f2ee3ed40e8
#TRUST-RSA-SHA256 144a7ccf4a8e19cc6c06dca79062d196329e60f4599351cba807e1857d1c5b427cb4a6ae14cd6c6a0828ab8190f043801e5dec2a65128c1cf046bdcca641b320746fcc64d85683965c2d90aa62364e3748c5cd7b3e4427ff847c643f47889e226734cadaaae34870dfad2cfe510e1f2accca352a6f954a229c36eccdf51e4589e58229627da178bf91f045d9a71bcf70019b59c08041d62a4cc0e574f6140fb0b185f5bad2d0e10e488611bf128c4307f08ebd7608638770cf0da4f23db6fcb42b0d4b396d854ff8de6b0d9ed2e65991b8e42201b94a39e635420a531a03e51eb2e376f3ca13f21c0e81a181eb15a78f9dfd3754e5e72a41107dedce7395b4acbc89ca07fe3c8622d0bd76326c6ef58027a8afc27f246ff1847c191bf824e8468212637712bc53f1590bad968af0fe601c548369f6a8ab6dc251f5c2b1aadeba811a7ec45f5e08cab02748229c195165798ca42580d1cb0e8022dcea3653c872cd0679a482e4face4fd98bc41c54c790405be8329da93894d66b8f23d2b57a4b1529d4bea4dcbb58f354334bb25a21bac0165f12e92f3e531dff85468e929e07d3666d0e0be03b662b86cdc650650605144474ded18efcf963192e25dcb3933489be562be0c7e56ed5efda2fda38085a5c959fc8d35ef3118e47eff97728183434a79a0bbc1b9d659c2db207e0663149ad650da633805eda1626a56ec5c07207
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103668);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2017-12233", "CVE-2017-12234");
  script_bugtraq_id(101038);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz95334");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc43709");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170927-cip");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"Cisco IOS Software CIP Multiple Vulnerabilities (cisco-sa-20170927-cip)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
IOS software running on the remote device is affected by multiple
denial of service vulnerabilities in the Common Industrial Protocol
(CIP) feature due to improper processing of unusual but valid CIP
requests. An unauthenticated, remote attacker can exploit this, via
specially crafted CIP requests, to cause the switch to stop processing
traffic, requiring a device restart to regain functionality.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170927-cip
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8057e067");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs
CSCuz95334 and CSCvc43709.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12234");

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
  '15.2(2)EB',
  '15.2(1)EY1',
  '12.4(25e)JAO3a',
  '12.4(25e)JAO20s',
  '15.3(3)JN',
  '15.1(4)M11',
  '15.3(3)SA',
  '15.2(2)E3',
  '12.4(25e)JAP3',
  '12.4(25e)JAO5m',
  '15.1(4)M12',
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
  '15.2(2)EB1',
  '15.5(3)SN1',
  '15.3(3)JN6',
  '15.3(3)JBB3',
  '15.2(4)EA',
  '15.2(4)EA1',
  '12.4(25e)JAP1n',
  '15.3(3)JBB7',
  '15.3(3)JC30',
  '15.2(3)E2a',
  '15.3(3)JBB6a',
  '15.2(3)EX',
  '15.3(3)JPB',
  '15.2(2)EA3',
  '15.2(2)EB2',
  '15.2(5)E',
  '15.3(3)JNP2',
  '15.6(2)S0a',
  '15.2(4)EA3',
  '15.6(1)S1a',
  '12.4(25e)JAP9',
  '15.2(4)EC',
  '15.1(2)SG7a',
  '15.3(3)JC50',
  '15.3(3)JC51',
  '15.6(2)S2',
  '15.3(3)JN10',
  '15.2(4)EB',
  '15.2(5)EA',
  '15.2(4)EA4',
  '15.2(4)EC1',
  '15.2(4)EA2',
  '15.3(3)JPB2',
  '15.2(4)EA5',
  '15.2(2)E5b',
  '15.2(4)EC2',
  '15.2(5a)E1',
  '15.6(2)SP1b',
  '15.6(2)SP1c',
  '15.2(4a)EA5',
  '15.3(3)JPC3',
  '15.3(3)JDA3',
  '15.3(3)JNC4',
  '15.4(3)M7a',
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

# Check for vuln version
foreach version (vuln_versions)
{
  if (version == ver)
  {
    flag++;
    break;
  }
}

# Check that cip is enabled
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_run_|_include_cip",
                              "show run | include cip");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"cip enable", string:buf))
      flag++;
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
    bug_id   : 'CSCuz95334 and CSCvc43709',
    cmds     : make_list('show running-config', 'show run | include cip')
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS software", ver);
