#TRUSTED 86bfb20e190e7a504ebdf01bea82cadd407ea1f6b700aa9a7098cec09a4c17db3a78542a6705183474068ee90453e353d3491ce5d40e6949ac7cda80a3a77bcd3b3f54f5c2def2b0e3c971e57a18434d90965180963a711c7e390ccffa794e07e3f3d2c49ccb6c5657f78bda5b002ad2d12c418436d7e2290292d5c64d58fd41d4f14cfbc78c83e7b99cee915bab8ed016529e8b58675bf1d87e37a3791502d57b784818224b8bfecd89e4b78f7307350d6b86e5a65d2ea4ebe895ab795c2a1fbfa779a7450aae49060cdcbbb310f2352e42607e4b443acab0630d8df666accc8d79d4ad0ae1db2aa81f3c5e9e6c8fa541cd12327e1fecaf003b8892fbf2b33b6bc2277653bb852f74ec32df3b43d2bd8789abaf219f5632ee62800cbfb800fc1c2dccaaf27076842c8d53389fd4c91419fcd65098adc33de5cdb8a7172f9041a2274096f25e32fdc68304ba5b5c976bfbec4f22f6a019f8a610d63afaf513253d8ea454456ac1cf33d421aaade7bd43f75d846dedd4152b97501bf276ce94505d6f2c30faedaca2b54e714d635e12a4c8d6b150b8bbaae26def925a5df2a7b0710b9880e8ecb9c5083fa325f2e293b33608cbf1d6d0f4b8c6baef5b7872e0afb3df831270a580f2bd034733df1ba4a30b272fa4ee437a377763feac9f6c777161eb229431d208395fb157190d75657607e113d0dc779e5448db261e4fe63e6a
#TRUST-RSA-SHA256 7237fae15c8e22d9ee0e9f627946712a8e4c519c279d724433dcb766bc99e05faba33280eae6700f90ffaf3fc8e707f04c3f672388704db3257cf86e85f1e7c7ccea22b7d530dda80ea1e1daa910992c9815b57365eda6cbfa258d4bb76ae96b484b7c06aaf125b21314e3688e1686ade9f8fa05c54d3b448af167ed2ff9ed8df50c5647d1dccc27cdf6f84113b478142d3146c4f4faa4e4d0e78293bf20ccbbf569169ff916470fa5c6ac00baf0bda2c6359409064a34cc42c14d9ba87b8eb604facdcd1b817ab1930574465077a8bc5782bcc41abe92935b9d1e785f2879a23019c5cf8249a177e9b813f4e186a74522d88c4100f9c349312613c148a6b5b12fea845c15ebb410fa4034409570866973dee78602574fd192f9d9acd252d7c3e576f90949c16b28d03e89416f105024a95cbff0f580020d226d699051508882657c9880c43e0b56f92d224b78eb142045019be86466c167991e434aa4ddf9ee70973cf70270f77ac73a95face3ca9b4595b2861c9e1450a3c9de09d786658dcb4da524c42107461993a76d6342cf9e6190f6dec2fba9122999249a42cfb21babf1b64387e64d46bc43ef1ab52ea33854c2862a3894132ea1ec9c80ef36cb8ec2f35594ff67b86e31a6503c9b6832a4327cc55c05075648a8522b4989a245e6db7b1d3910a5fc733dc22211b2e2467a2a40b71003e5a8ac873b165258a72db2c
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136623);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3285");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq93669");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ssl-bypass-O5tGum2n");
  script_xref(name:"IAVA", value:"2020-A-0205-S");

  script_name(english:"Cisco Firepower Threat Defense Software SSL/TLS URL Category Bypass Vulnerability (cisco-sa-ssl-bypass-O5tGum2n)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense Software is 
affected by a remote code execution vulnerability in Transport Layer Security. 
This is due to logic error withing SNORT handling. An unauthenticated, remote attacker 
can exploit this to bypass web traffic policies blocking specific URLs.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ssl-bypass-O5tGum2n
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14e8f395");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq93669");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq93669");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3285");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl", "cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

vuln_ranges = [
  {'min_ver' : '6.4.0',  'fix_ver': '6.4.0.9'}
];


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq93669',
  'disable_caveat', TRUE
);

  cisco::check_and_report(
  product_info:product_info, 
  reporting:reporting, 
  vuln_ranges:vuln_ranges
);