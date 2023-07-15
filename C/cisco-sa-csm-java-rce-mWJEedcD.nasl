#TRUSTED 2fcd4593f5d7a6788333c97549d39ea616d2d4ae45d7ba59399c8e5d013d9fd9ad96b14a48d5f5ca95de832e3f8c83ff03da9e98f2687e4e6811dcd8231f200caf21ad90dbf3bc30d9b2f1f8e13171605d1ac03bb1e6c58213a9c66defdded1b10640dde7d5b9cafb06cd8970c308c3c871bc7a19292f862861c547191544320ec25763753b4e9579f0160e8a293a050baef5b1749a62022066ad270332525f1382dd5464f4504216aa507d1dea80b7564d7a53d803ad8df4107969d61aafd1e87a49f35a98a92134d218bea6f4506eae5b78d9efcbc88e219f9e969eaaf7da52ac8687ff92be5bd0b7ac727eccffd07b4ac74169c05bca7da7fa5eeeb41ad65695054615172d04ab755cac2e2998fd44b3a460b250686016b104ccd3765a0ffcf7766efd1b9963c1a59330fb4f9def31e3f948a6ba3fe5b6eda4282f85b2ff302fefd0e02d6b9315bb9e7dd835dd1545e6a0c102fbcecee488c169dc71fc7ec1c469b5bcc41995ed624f8584cd81686b2fe03e9902d578a696ca566cf0569ef1ff059fdab5bd6319d54f9a496d4b709f6cc928a99a5b57144ae1d2e709b174b35d73e85712ca2aea8bff222704a8121be5c32f1c4e3fd16dfa41c7f887b73a91e2aa478a28f72be274184986b54b8cdebed0cdca560df75561b293a1409f8a5fb249343468c7ccd782eee55136408cbf92f41edaa235778777775583a41751d
#TRUST-RSA-SHA256 16f4d70b5f50cb44bad3291bfbfb4c3fd0235377af174dcbecdf82f0fdea72fc94187c57f369de6bb4596b2c682ad18da9381327ea1270bea9e7d9b34dfb9496cbe8bd615d071c092e89cc27738807378dcdc5ea7e3a37a56533fdaf89a3204ea71a12f9d86d7d81d218baafa7263a045eb44ef1ae90077b7722109c2701ff3a72be336a921af8823aca61a3fa885198abddd9f0ad332a781b886508c1ca093585acf78ba0d03d035c1a34e43639ee0ac0f8a53cb1af87057e8710b928c8453e5a0d61818479b4502c22956d8af0e5fa9411b46d557fcc6e85097b9b76d8e8091e2f900eb5cd68977c65ec10618a645db174147224353309d29c5ca70316b26858be8358b10f6e08fc4c52793e18fb55d04e47ff89d2ce853bfefc9ad7f29689728e1f7daefd7dadc0568b78bee64a991a5b29aa1b22e2294184aca662dec05929abd2ed49d8ec658175ee320e2a5542925993b589ce104935a07648fabb33018bd00a2439e8f7e5ecf5c208c8bd320ca064d316923ec6c61cda3fc83ac419357ba9794c51fb7bc2ab1f7becdb9c4283ead63542c0a29aca30052e492de0946f6008ec3768c918467dae28d95afe12682787351b3a3b0a44437e4da7a0a00cf2154137f5f5eb6823dbbe33a5b3117f56a70970320b01a8ce4376b46324f990493dea2b1182fbfbe163cfe4f098df336a0f1e56f1905a4c905ae99c41b38e6e82
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153258);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-27131");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu99974");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv79824");
  script_xref(name:"CISCO-SA", value:"cisco-sa-csm-java-rce-mWJEedcD");
  script_xref(name:"IAVA", value:"2020-A-0535");
  script_xref(name:"CEA-ID", value:"CEA-2020-0136");

  script_name(english:"Cisco Security Manager Java Deserialization (cisco-sa-csm-java-rce-mWJEedcD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A remote code execution vulnerability exists in Cisco Security Manager due to insecure deserialization of user-supplied
content. An unauthenticated, remote attacker can exploit this to bypass authentication and execute arbitrary commands.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-csm-java-rce-mWJEedcD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ead11b1");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu99974");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv79824");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvu99974, CSCvv79824");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27131");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:security_manage");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_security_manager_win_detect.nbin");
  script_require_keys("installed_sw/Cisco Security Manager");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

# get_app_info wrapper converts version string to <version>-SP<service pack>
# for ease of writing constraints
var app_info = vcf::csm::get_app_info();
var constraints = [{'min_version':'0.0','fixed_version':'4.22-SP1'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);