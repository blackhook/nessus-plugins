#TRUSTED 4b5359251bc7c826f598de5da848a3945b8071e2886bd0335bb2986ab5fd7a5543f9e511ced3e71c7354b49f94a50f16d147951924579ddbd460aa52c08dba7f60bd93f3212dc2031f7a69c005b84bd663137f357c20a111671135c1d3d9d6fe6f71efff50ff576077a2327fad90fbcde8c32c61f3d1670cd7a3383c185c3c40109bdd8afd9c3483621037e42b198b2527a9f424806506a91acda138ea33535f3e8385c6f702a7ebe12adcdd97c758d6a22b863541ab1b0b45f8c1a53960687b121ebb92ce834ee3d4750637dba3e579880a71233e54534d0404b206a5a6b1153717cbd43d4e6f33c715cafb44bfd5b95b58247ed4fb7cf555823f6ee6708d57525982743c70d7ebc28c7a6decbbbd6ef8bf18358269911c63a864ee7e4f274ca7d6a6b1c5fd03bb70f711bf87ccd391b601f5d325d40030a7ed201c8cb9f62dcfeca8fed986a1acf89dab56bd207f3fe905e099d6c2c39ac08c621cf07ad96a5a8d45ae964dd3c68c759b303373af2860b1b052d03cb5942b978e62215df6ffd995ef412e869365003f59770d95dd79bc0842838b7e34cb0bba1ea5909b31fd1f41576796adf93b626a4ca04cbf61040dc8c8df7a0ff4cc70d22c7598a19dedda28ccd948b66993de1cae2afebd146543e8fb34841ca15006db05372949eee2883fff6fd840bdee03c5970c280be39d480b2b9e591f1529f64f66c09fb91eec
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139517);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-3216");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk38480");
  script_xref(name:"CISCO-SA", value:"cisco-sa-auth-b-NzwhJHH7");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE SD-WAN Software Authentication Bypass (cisco-sa-auth-b-NzwhJHH7)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE SD-WAN Software is affected by a authentication bypass
vulnerability. The vulnerability exists because the affected software has insufficient authentication mechanisms for
certain commands. An unauthenticated, physical attacker can exploit this vulnerability by stopping the boot
initialization of an affected device. A successful exploit could allow the attacker to bypass authentication and gain
unrestricted access to the root shell of the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-auth-b-NzwhJHH7
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?52d778ec");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk38480");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvk38480");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3216");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/SDWAN/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE SD-WAN Software');

vuln_ranges = [{ 'min_ver' : '16.9.0', 'fix_ver' : '16.10.2' }];

var model_check = tolower(product_info['model']);

#Model checking for IOS XE SDWAN model only
if(model_check  !~ "^[aci]sr[14][0-9]{3}v?")
  audit(AUDIT_HOST_NOT, 'affected');

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvk38480',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
