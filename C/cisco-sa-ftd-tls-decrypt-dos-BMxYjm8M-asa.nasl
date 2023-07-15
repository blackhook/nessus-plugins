#TRUSTED adac4d49d0db58aaa6e6f86438496459ec8212eda7f4774012d2511ddbb66eca97724727e6068e04658aef91ca18c72776d80629c60cbfa09295db3a25b4982c9e34723bbef28b6f6621e5b57ed3bc6c5992c7d4da3d14bab9610b2bcd93743b7c45d76b6511749d590d035ca4822f8f3e15d1ced266915cf346246017fe64fd856206d12336a14d007af6a9c2aa12ade78578be37bfd8d5e83f15a018d801e7ac36387caf41381b7437159d61701c4b6e789d39dbe0f019e03a9c690fec4c4db120ddfca091eee288c36d6cac01e60eb630ce383976efbe5fab9914dce1e6e1713fa68400566b42e4cd56078f41b6f65d62f9ab4957b7c21ed9e2b718396793c90a3c5f0e884042dd969634b193c93003ec6f7576f28cd1ce6ecf54be188c04f4d39cf47a49f01fa7ad2d0daae88caf05e2ca91f8ebcf0fcfa2cbf7142a63d2e1ce055103aa2693876925da9579fc3762986d6e055ff1edcec3f4429416e76280639486cdf0c393d65271da7efaf94e2aa52ddc35f4fa6200808a57890946bee8f3828048568335bb57113a2c30851229cc1e8204ddb5d6d0e35729f4b7c9aad92400446727fee494bc1f5846809e30ed5ec3775d8b0e67c50e6ce68bf6f4ba5044fd72d028fc10c1e6bddca31d52dfa000612c1e637193d794f72818e90fa67f04a025a75e9f797053879d053f78f5968f151e3063bbc9ecf5d5ce984afd5e
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155450);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-34783");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy55054");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-tls-decrypt-dos-BMxYjm8M");
  script_xref(name:"IAVA", value:"2021-A-0508-S");

  script_name(english:"Cisco Adaptive Security Appliance Software Software-Based SSL/TLS DoS (cisco-sa-ftd-tls-decrypt-dos-BMxYjm8M)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco ASA Software is affected by a denial of service (DoS) vulnerability in
the software-based SSL/TLS message handler due to insufficient validation of SSL/TLS messages upon decryption. An
unauthenticated, remote attacker can exploit this, by sending a crafted SSL/TLS message, in order to cause the device to
reload.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-tls-decrypt-dos-BMxYjm8M
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ddc29d7");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74773");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy55054");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy55054");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34783");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': '9.16.0', 'fix_ver': '9.16.2'}
];
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvy55054'
);

var workarounds, workaround_params;
# Additional workaround for these 2 versions only
if (ver_compare(fix:'9.16.1', ver:product_info.version, strict:FALSE) == 0 ||
    ver_compare(fix:'9.16.1.28', ver:product_info.version, strict:FALSE) == 0)
{
  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  workaround_params = WORKAROUND_CONFIG['asa_ssl_tls_no_dtls'];
  reporting.cmds = make_list('show asp table socket');
}


cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
