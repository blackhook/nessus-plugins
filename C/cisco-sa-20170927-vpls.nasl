#TRUSTED 8c4db4814f714920a8fb4d97ab636b46712013806d77b536e6c95c45afb832fd8dabb0a017d6b5951e6bc700d6c1e948f8f4f54a6e08e909bd93ba72f6bc9f9d77271919486c011b100449171d45c88c5c1e35a3a138d0d1174415b3269546e3cd5f6de4e938a6d18430f6c6a63265f7d2135b8bc5249c1147653beebbce31bbbf4839c703aef2e498ee63a56b240236c6b34094092754b323ef19182e1d4b4465819e7328b60fe19f42ad4fca7d98219bea65e5c625159e1f760c2cfbeabcc85fda08e6d42ee0295bf7e087b2477ba69030d9ab187ea87e4d773000141914ed1aed3268a5cd8ffb547b90fd8f13273e87660a670423adaf52800c8f0e8ab78740bf1c6614eb8f4f95949d55028cbdb319e7ceba42d1bec73ae9ae457c5e531b8062fcc25c4c4cfbcef16e8c1b0035f1f3831757d065647aeb32ffb168555c6f0ecdc005f71e129e09586e2ceada854cad1d456cbcb421c7d149dbc99f288f40d627cac9e9071f5a24c958d847ff37cf5899720c6c192036ab742d9752775082085a3b6288229f7cfd82e1bd720884369586490c8287299ce4c433855425a94fb3bed81424a039f288f1e6a7d73c19054c58541bcc6fe2b5b30e8983fc21435c5a60d46bbe7b439a632556a962b9ca9b71d7f88e9a889b3a326268a35167ef31fcdae1061c0fad0918007cf99acd1918bb93259df27ceda742b2fab949038edd
#TRUST-RSA-SHA256 7428b4b3a9460a5abc678ddd91e2ce38766a1ea6f657d11bd9f0506bc74ae821b94f1964b3b4d3566dc6c55a9cf75dc67afdd4d31cbe419bf848fb1813a0e1aa4517bd4e3804ed74daeb9990d26f0acb8e1809caabe89ca0ed26407b16b92549c10817364980ad485780b991e4e929ded0eec1c9012e91e73a289888efe4e79cfb496c884f0ba21f7f7f5e2192780645508156b8e911e5428420e2e493ea3e66c89dc2401ece173c35a21024cca13b59d2e418ba3cfd6b4a7adbfbe3ee287e004db62888494d80490876f3ab41bde8672f641b5aaf28c7f71802504d2e85a2d51adaa420df20c42d1d610a473af63617c0c203574452031bdefae9c2f3911e5e3d9f63bd97533d8d8531ef9d9ce272b83e5ac7def1c4e8192294999ce137b715e4e78f7e6c080e82ff9163074a120d6abf03b2a3f4ab559411383c260f12e580199d72aa3ba48f5eb34eed521fdd2c7f39802febfb39f75a3127f5344ac26993efe14928f252d4caad67eaa8975f3a7b381ec8fb4578da29fa950a172c2403ac52bc30eed6bf456195433cfd15a58c3b620e428d4277a24124d69d89db036cedf4df17938a02fb08e163fdef58e191bcfee4a20c8ba61b7685e1103154932bfa3cb76a0472bb5aedb7d915e990d330b7744a4998a2e6a83c926368f5d975058aecb85bcdcda0154c56e20c27d00fe2c47684c756602f71b60c0538ad57fb724e
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103672);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2017-12238");
  script_bugtraq_id(101040);
  script_xref(name:"CISCO-BUG-ID", value:"CSCva61927");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170927-vpls");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"Cisco IOS Software VPLS denial of service (cisco-sa-20170927-vpls)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
IOS software running on the remote device is affected by a denial of
service vulnerability in the Virtual Private LAN Service (VPLS)
feature. An unauthenticated, remote attacker can exploit this, via
specially crafted requests, to cause the switch to stop processing
traffic, requiring a device restart to regain functionality.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170927-vpls
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7982d6f3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCva61927.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12238");

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
  script_require_keys("Host/Cisco/IOS/Version", "Host/Cisco/IOS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

model = get_kb_item_or_exit("Host/Cisco/IOS/Model");
if (model !~ '68[0-9][0-9]([^0-9]|$)')
  audit(AUDIT_HOST_NOT, "Catalyst model 6800");

vuln_versions = make_list(
  '15.1(1)SY',
  '15.0(1)SY1',
  '15.1(1)SY1',
  '15.1(2)SY',
  '15.1(2)SY1',
  '15.1(2)SY2',
  '15.1(1)SY2',
  '15.2(1)SY',
  '15.1(1)SY3',
  '15.1(2)SY3',
  '15.1(1)SY4',
  '15.1(2)SY4',
  '15.1(1)SY5',
  '15.1(2)SY5',
  '15.2(1)SY1',
  '15.1(2)SY4a',
  '15.1(1)SY6',
  '15.1(2)SY6',
  '15.2(1)SY0a',
  '15.2(1)SY2',
  '15.2(2)SY',
  '15.2(1)SY1a',
  '15.3(1)SY',
  '15.1(2)SY7',
  '15.2(2)SY1',
  '15.3(0)SY',
  '15.1(2)SY8',
  '15.2(2)SY2',
  '15.3(1)SY1',
  '15.2(1)SY3',
  '15.4(1)SY',
  '15.1(2)SY9',
  '15.3(1)SY2',
  '15.1(2)SY10',
  '15.2(1)SY4'
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

# Check that VPLS is enabled
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_vfi",
                              "show vfi");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"state: up", string:buf))
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
    severity : SECURITY_NOTE,
    override : override,
    version  : ver,
    bug_id   : 'CSCva61927',
    cmds     : make_list('show vfi')
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS software", ver);
