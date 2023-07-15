#TRUSTED 3edd72bca2137ce5051587a63685df8b6509ae7b4f8251d3d4795915b879a1ff8072abf2e90f17a28c4beddc409fb6b8bc1a89ae3e00db6cb824e46e8b50f1b7d935fea7fba5883816a2a82533e38f648aac6334df43e32606bbfda5355ba953ab983ce56e1c7faf01b9e96e168704c5b772e1b8fc3467ad54c6fa1d8eaa1d3b94e039530816417a6055fbbcd79014ea9484169bf0dd9295592701178beb2effb506c372d606e575526f8731f6a10c07e21857ce8dc67d392c0f340b51c328b95c809a2ee2ecaef9e037f4af4043e1dd802beff08e861cc444445fbf8207f88a450abafe152cfa115cf2e106e62347591d37bca89892cf9eae0c335c10aee170bd30a950dace9bcab4e6a6c67934515648582fe3714ee888ec2080ea74138aa0831903d1d35609f23fc9fa0ba378f9655ab1cf2803240e8b6b8a6f59d0b7fef206128b3d3acb5e3328a5f2d8c56ce8d323939967b822558e6bd8fd5a4b53649ed22851f1d4ee2ce75213a2c5ab464cab9616dc55538009dd2aa22c358c39aadddf7ff5b3e79dbaf8f85ec26f960b418ccce03977224c58a9b5eef7eec2ef88c173b721a65a44dae1b357e3180ec665719c442c13fc3a1a34dc0dce4af0ae33caeae68bdde161545dcc2ec4b5abb94ffebbb429c907dc3d1afbbf1de210d1be97a578e56c16f26d5aa8ab02e35bfb651d7e08357f2cff9b52de510a3ef0f29e9f
#TRUST-RSA-SHA256 63e45ccd0f2c248efb91db5d43c70e0b29507bf614c58ed58f023c58eb4eba03551f1462f3fa4f26b0ce2e61c271aa4ae654ba265ec60f2fe2d4d8a2883e79542e2dd46aef194e299afb5dcb7287ecc2f579b050fe593518cb0d9d6b7b7d2fff213a835151255ba6b64bee403e9a44726095f5a40bafc07aadda3bec967f2e455314859bf77c4d2220c455145dc9036de26ffaae77fbb7c1201ab9d44be5ae62a009f50d8e635a31d27558da4f62146e65a4703de1b931b82187b7468d4d45cf6ae170b9aa3990e569043b9074882cf2eec68e01c86575dddabbef2e9c633b439daa2a5f0adb60949935c6eff78ea28c2a3a21a9cb0f69867697eb4140d74fe40a756dc8020e979fb1933ae99424a7f2c7eb3d7cd665f29cee7a152dd04e5c8c0c47b3eec314c2dab0c962e298d5b8bd6c7aaeae7398f832347e94efad1b03d27086935cbb82f937ca99c9e8ab69846a9948cbcd185e6c6e650b2f589e15111012eebff2a7128e7cb1dd84e076a3b9af12d39e3e2e56ac8a958c0b84f17bbb23224db7ffaa3edb93c18c4a410b07180bea381e9c4862a2bd6cc30f08d459678a828e11b014a6dc0648a488afc1a1f649d43c52fe9d20422d8f00b183a0fa86f0cc8d1881bf63cef0a5276fe65750eda81236354bea7d496b2158377757908d82f4afd312146abbc8a6f843b4971f90381a579c90566e23341ff4ebb6164ce83c
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(139545);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2020-11896",
    "CVE-2020-11897",
    "CVE-2020-11898",
    "CVE-2020-11899",
    "CVE-2020-11900",
    "CVE-2020-11901",
    "CVE-2020-11902",
    "CVE-2020-11903",
    "CVE-2020-11904",
    "CVE-2020-11905",
    "CVE-2020-11906",
    "CVE-2020-11907",
    "CVE-2020-11908",
    "CVE-2020-11909",
    "CVE-2020-11910",
    "CVE-2020-11911",
    "CVE-2020-11912",
    "CVE-2020-11913",
    "CVE-2020-11914"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu68945");
  script_xref(name:"CISCO-SA", value:"cisco-sa-treck-ip-stack-JyBQ5GyC");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");
  script_xref(name:"CEA-ID", value:"CEA-2020-0052");

  script_name(english:"Multiple Vulnerabilities in Treck IP Stack Affecting Cisco Products: June 2020 (cisco-sa-treck-ip-stack-JyBQ5GyC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco ASR and Virtual Packet Core StarOS software is affected by multiple
vulnerabilities in the Treck IP stack implementation. The vulnerabilities are collectively known as Ripple20, and can
result in remote code execution, denial of service (DoS), and information disclosure by remote, unauthenticated
attackers.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-treck-ip-stack-JyBQ5GyC
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aa7d662e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu68945");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu68945");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11897");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asr_5000_series");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asr_5500_series");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:staros");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/StarOS");

  exit(0);
} 

include('vcf.inc');
include('cisco_kb_cmd_func.inc');

get_kb_item_or_exit("Host/Cisco/StarOS");

version  = get_kb_item_or_exit("Host/Cisco/StarOS/Version");

# For newer versions, We may be able to get the build number during detection
build = get_kb_item("Host/Cisco/StarOS/Build");
if (!empty_or_null(build))
  version += "." + build;

# defensive check for the pregmatches below
if (version !~ "^[\d\.]+\([\d\.]+" &&
    version !~ "^[\d\.]+([A-Z]{1,2}\d+)?\.\d+$")
  audit(AUDIT_VER_FORMAT, version);

# In this specific instance, we can remove letters from the version and use vcf.inc, since there are no
# letter-containing versions around the fixed versions.
match = pregmatch(pattern:"([\d\.]+)([A-Za-z]+)?([\d\.]+)", string:version);
if (empty_or_null(match))
  audit(AUDIT_VER_FORMAT, version);

app_info.app = 'Cisco StarOS';
app_info.version = version;
vcf_version = match[1] + match[3];
app_info.parsed_version = vcf::parse_version(vcf_version);

fix = 'See vendor advisory';

model = get_kb_item("Host/Cisco/ASR/Model");
if (model =~ "^50[0-9][0-9]")
{
  constraints = [
    { "min_version" : "21.5",  "fixed_version" : "21.5.27"}
  ];
}
else
{
  constraints = [
    { "min_version" : "21.20", "fixed_version" : "21.20.2"},
    { "min_version" : "21.19", "fixed_version" : "21.19.5.76949"},
    { "min_version" : "21.18", "fixed_version" : "21.18.7.76959"},
    { "min_version" : "21.17", "fixed_version" : "21.17.9999999", "fixed_display" : fix},
    { "min_version" : "21.16", "fixed_version" : "21.16.9999999", "fixed_display" : fix},
    { "min_version" : "21.15", "fixed_version" : "21.15.45"},
    { "min_version" : "21.14", "fixed_version" : "21.14.22"},
    { "min_version" : "21.12", "fixed_version" : "21.12.19.76886"},
    { "min_version" : "21.11", "fixed_version" : "21.11.15"},
    { "min_version" : "21.10", "fixed_version" : "21.10.9999999", "fixed_display" : fix},
    { "min_version" : "21.9",  "fixed_version" : "21.9.9999999", "fixed_display" : fix},
    { "min_version" : "21.8",  "fixed_version" : "21.8.9999999", "fixed_display" : fix},
    { "min_version" : "21.5",  "fixed_version" : "21.5.27"}
  ];
}

# Run show running-config (not using cisco_kb_cmd_func.inc because we don't want the cisco param to ssh_cmd)
# audit if not affected
buf = ssh_cmd(cmd:'show running-config', nosh:TRUE, nosudo:TRUE, noexec:TRUE);
if (check_cisco_result(buf))
{
  if (!preg(pattern:"flow action url-readdress server", multiline:TRUE, string:buf) &&
      !preg(pattern:"firewall nat-alg sip", multiline:TRUE, string:buf) &&
      !preg(pattern:"firewall nat-alg h323", multiline:TRUE, string:buf) &&
      !preg(pattern:"tcp-acceleration", multiline:TRUE, string:buf)
     )
    audit(AUDIT_OS_CONF_NOT_VULN, app_info.app, version);
}

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

