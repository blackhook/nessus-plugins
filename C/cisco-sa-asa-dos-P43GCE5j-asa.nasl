#TRUSTED 26e3492302e2de66da273239d649c75fe8e824c9c3e3a5e5aaa11bc7448e89ca4f1764830209b56a829f8dc1382afdee9935e0c3dc30756de3b58d86b48e4486068db32fd7b27082b3ee470322453c261de6d5bfcf64b036f108f9632c462cff9121340f07e9d98f9eb694cff6f1000a94df40014742727f09b6138e43376b83573462eda4780a02a5196753b98f0342fd4d4ae175b18ae780daadb454bc2de461ccf2143f24bb5b48d07028f4fe47955afa2424921b3c045f9d3213016f8bae2dbd750b134447ff815581bd1beb75177d9f076393543fcbe9b3e9598b16ec805bcc15f6d5e897c2cb9a9df4fecbbbd16884227fd78e869cd31a48f47aa3ca52d35b955f0d1126b63a4ec081302a25b74f44a1586047fc3183a47bc9fedee34816e2494d2ed3c84dd8abca64c4bb1999ee6bb54a3ef52a0dba83b2bb7f7f5ba6b6597f1da82dc22666c32e41b7e497d385192c4147320d14236b225980b387b11cf691fb6c0c6f792e836195dadbd43b54682f656c917357a3f1c8b0e57680a1fa92b8fc0db1e07da2d419641e1df725ec118816c57ab30dad071437f2ab951c5eeb577992982d0e20a76d4752078a74e732c4c4496e2eefaeb7506dead9da47f39087528779a431a4d0562b124864219106fd77c950f02a1095886d38dfb03d40561949944d763a73426f68b8ebc26910d5b8133ebef5f04e371a1785002c98
#TRUST-RSA-SHA256 70ee34d4b79ed857293d1cad841e487a3bcb8bd814964420101fb6fe212332e07a8ab30e17b8ad7f8acee852915c2af647bad032de92e5c55c3c90b2b2357d8adf9a4801d6702b400cf59cb6d3e9ddafb6416bc7246d50edd03b6f2605defb1bc7080e0684f125168c7d85b880d089e7f1c789671b45dd098d440a80017c4ddaa709867761d5e1ca9a45ebddbf9c25f55936d21f9f6ba4e62aa64999884fb92efb7f6b560d8d6ff99ffe923ea8cd569281a5fb1262bebd11019ed8f0ecd8f10fe0354fc0a7ec3300e5e98f637b5453ae5fc904e90bd39c15804d055921b2f4d70940d1aca0e9ee7a8324b0e5b73b41d93e1336333432c98799458bbfa29782c05d1fe6060132029ede04112539e533fcf0b892a5a8d6cb185be655b29dee183788d569c7ed904230bc6f479c34cacde6a4e2493ee805584061123de15363d6f99b0b4524184d14ba5803310b0392c9bd0a13b744698df12f1b18236895f0fef7fe001405b7a9635c21387c44dd4444a59a507eb831f2cca3a6b285463f20c9484edbefa2bd8d29b66b6006327676aba03e5913ac2579b0617f435ba14f6bec42a377a5efa34c2608cfa644dbf7c890c3b6808c7de2efe15b548d95377b15722ecb17f44cbf1fdd45ed8024ce1b9f8c179efc286ab6b80c57e80a97b0fb2b9f6a26f693c882c70231eeefc91e58bed2f27e5c24bdf00298ee51c8d986c3370a71
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136830);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3305");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq66092");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-dos-P43GCE5j");
  script_xref(name:"IAVA", value:"2020-A-0205-S");

  script_name(english:"Cisco Adaptive Security Appliance (ASA) BGP DoS (cisco-sa-asa-dos-P43GCE5j)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Adaptive Security Appliance (ASA) Software is affected by a vulnerability
in the implementation of the Border Gateway Protocol (BGP) module due to incorrect processing of certain BGP packets. An
unauthenticated, remote attacker can exploit this, by sending a crafted BGP packet, in order to cause a denial of
service (DoS) condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-dos-P43GCE5j
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?745a6bc4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq66092");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvq66092.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3305");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '9.6.4.36'},
  {'min_ver' : '9.7',  'fix_ver' : '9.8.4.10'},
  {'min_ver' : '9.9',  'fix_ver' : '9.10.1.30'},
  {'min_ver' : '9.12',  'fix_ver' : '9.12.2.9'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq66092',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
