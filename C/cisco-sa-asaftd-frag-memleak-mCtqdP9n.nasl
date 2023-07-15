#TRUSTED 5867a4be038fcd1ec791cb6a9be9ebdf49214b9e7f5bd8446c6708b68f1f14cabb8bbd615019ff86cb30c034b0b5c7185f00b263d2ea0910446ebdb43137a631f2238875c2849e4bd1ac780f57751944df427148927059d1ebbeecd61417594bc7f90135e1289393391a659f4bf027485ff4b0d442d5ea77ed0ab6e42222cbd42af9e039ab8533b5ac3ca4388d941f8e14db4ebf942aad2b264180140c693f9d70d62fc9c5cb9c8900adefb1df0424b56af00bc9674b51250e96312221328d001eba54b5e2579581b865eb6f2fb7b7ac27041ca19054e7feebd061c8c2c25f76a5dcdd904067a1928572a47416d7319bbf221e64bdf507f38ecd4bcc5583c1dd9df420abcb0334ccafef5504c6fa5eb1c41eafe3a4576f56e5338f2a277d98c6fca3a14a4a80f27ad1899820dfcf97e2f9dfa9fe8ce5b16f4093381a850d02bbffbf5ecf408b3da1fa6e3397a2bdeb44323bf0e848201d8be58ab0b72a8c36954d055b3234afa96d7d136b7c139e473adafdb4eedfa0b005dae3dc26b1859fec983f921ebab1f3d58f56b1ec38229ccd3667011e46ff44688ca189d682697b99b89172dc740001c3564b5a38b8bfb3f931dcf6aeda29957bf74fcc920bff97952e41b54ab1923ae23ffeef7cd1de283a65555d411a7e649a40077d7639ca8ded81fb9b9ae185238d803e8f3dd954c92e6b5b4af34c4ad0f14b1e5113fd4a682a
#TRUST-RSA-SHA256 0f5e932fb1b0a4ff81c73af6b053b821f1b4f5210a107bde9e97eccbc8f3ede7ae8006a69bbb11fcdf92284b1ee60b023b6097f411c936d24be385dfcf15bafe789907e3c6ea25144e762036eb32516e5f16c75430aff2c2f4505727370ea2cba1abbe6902ed9f7757cb301c2ba2fe90a78c7aa880867996655d4cc6ecb468e05268f8777e6e79e214346c3ecdeb0e1165643014e79631230e97f5b99a93de9c9f4d702955c06f53d1ae0c4940618f1fb3dd9c4d78210921d619ee93e40aa8252c422cfdc4783752d0d4a0c4215f064b5e6bbb5153302a896b91ca4f9f12c00670e35d44917ccd386b117db03f7236ddbeb8fe7321a8a10606b46831b725e5c70176a1b8ad04045d44649e06b0a5f233e46771fb0f64a97503e15a47b62adcb3afacf399aec0c72e38defd60ff080350b4288ddab50ca9f0a0d283b82d59ed2d12b3990e64568a9017202e642005856d7c5eb19d9e083c2c68423338839dada735a0bfa2800098f3bc53221df4a7b03de72056d142526448d215b07ca67d2eb645a0e50625b17b94a58a1d12909311558768419cc0d223d75683139cbc95421bbfe0dd99fc706445164f3d5a780eb6d9e81512b5d451989ac87c65f928ba797047b7d381d51dd5308de95f34498094fec5b79ec20ac64a1a36d7993553e41291f0a1b4852b11d02ed0e59b66353c3b83d2e6909bddabd11bff00876949847aa0
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149852);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3373");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu47925");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-frag-memleak-mCtqdP9n");
  script_xref(name:"IAVA", value:"2020-A-0488-S");

  script_name(english:"Cisco Firepower Threat Defense Software IP Fragment Memory Leak (cisco-sa-asaftd-frag-memleak-mCtqdP9n)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense Software is affected by a vulnerability in the
IP fragment-handling implementation. This allows an unauthenticated, remote attacker to cause a memory leak on an
affected device. This memory leak could prevent traffic from being processed through the device, resulting in a denial
of service (DoS) condition. The vulnerability is due to improper error handling when specific failures occur during IP
fragment reassembly. An attacker could exploit this vulnerability by sending crafted, fragmented IP traffic to a
targeted device. A successful exploit could allow the attacker to continuously consume memory on the affected device and
eventually impact traffic, resulting in a DoS condition. The device could require a manual reboot to recover from the
DoS condition. Note: This vulnerability applies to both IP Version 4 (IPv4) and IP Version 6 (IPv6) traffic.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-frag-memleak-mCtqdP9n
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e9d5e6d6");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74302");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu47925");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu47925");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3373");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_version = make_list('6.6.0.1');

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu47925',
  'disable_caveat' , TRUE,
  'fix'      , '6.6.1'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:vuln_version
);
