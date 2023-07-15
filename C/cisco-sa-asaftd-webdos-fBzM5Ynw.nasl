#TRUSTED 5f12b9fc47f2485e9f6e4b67845961081e6d51c00b70c99ae0bc97b4a901569e0b0cdf2cd17087dc563d747e7de05550f2c59a691d6b20dd47603db66379e225a5b609907daeb95af43f013e10e43dcd8261e9832d45431719438b79b0a7977f9abd1f09470c15aced812f0f7b044e6f970ba18da0f52ece854ef190d474ed9bbee5d4b1d9ee9ae884672861f2e78e4e51ac78e9d86367ad7241bfe751bd9a8c795c09c5d025844abaf5348a8f5d98c12b53808deff4901d9c3f93c5af560eef0db3ecdf5ba442d93c59c0607c04b24e4413243929f7ef346c9728d0635845ec504fc8a650f9541dd54311798f6fba42d28368387ab5bdbc35e15ef4d0862280a856b06d7c54b95c449ef39513f78b05db86e5da4e62f4804a3f8d04274c1c5c765607c43a521df05f90c53e27449c3bd04f3a77fad54792a395351f1eb9e112478c0beceba998389573c70a16da2794c2ecd216e64449bc9d4514def7ec870b0a141724be1b0f277ad3ce757057d893e4f58816c30d45f34ce6fc36c0708eacc8239a7be1f8a99202f1d848022bc3e363929dd295bcf679a6175809ef9457a3c009a5027a059ca33d1d633bbd2126595a20dd26a7f7c7a45beb7cc787689154b17c3f63eaca848475a24348cb97d6bf086f690602e2c1ac4b32db9262646ea96d295b1ad277912859cd11c602fd6a8c36353632c0762f0750e9a159a875889b
#TRUST-RSA-SHA256 5dc6a3c2a240f8fb01f83e614a46f3e69409c7b6727e80bd0046d11d0a860fde7c704284c5805bea752fc22f974993c55943fcee1ed196710609d4566124cdf2cdd05cbd995a6352a411e242b6264339576290fcfca98290dce0ab52eb3ddead060372dd889578e26948b912dd9cd79a4d25d7ec555d9a7c7c2205599e1eaf3d35388304c39df34f8a753a792c38d9797b4fdf05908bc8cc3c72db077ed223ec01349553cf7d4fa976aeb49498f75e0907340f4e53830ece1808ec7cb5c59f68f7d681b6907ab967739c4cd0a2d439846037554137b1b650454b31a56755035508615a04392964efd597098e2cc9239283be594d050997c82645834df3ed5284c1dcaa2d7d81ea70c7313d8022515bba19223977192040033e4147535d76c154a5a09d598cb9fe15234125309f848eeda6dcddaf1aae88ceaa0a2a1bdcc8ef37b9b783435ff3bd9faf7931f6a0dc4a1596e08f28d2ac4460e68a58267c02bdb3107931632146d86988e723b344caed632400034814502887a22a69085a75817a9c69e1b833d77b3570b4c0f4dedff8b5bb7b2957adaa9ce958f23f8a469d668ad24431273e451bfeed9b03e359e7ad657e270e0c3db0eb4460c39402ec0322f4b2206049667531764a17762b784fcd391c0441225f1df367bf4200fb2e604ab7baf2bfe84024c07ed764475d5971209dab39dceda9a789b66aa2fb42cc813192
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141830);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3304");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs10748");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt70322");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-webdos-fBzM5Ynw");
  script_xref(name:"IAVA", value:"2020-A-0488-S");

  script_name(english:"Cisco Firepower Threat Defense Software Web Services DoS (cisco-sa-asaftd-webdos-fBzM5Ynw)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense Software is affected by a denial of service
(DoS) vulnerability in the web interface due to a lack of proper input validation of HTTP requests. An unauthenticated,
remote attacker can exploit this, by sending a crafted HTTP request, in order to cause a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-webdos-fBzM5Ynw
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0fb5929e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs10748");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt70322");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvs10748, CSCvt70322");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3304");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "Host/Cisco/Firepower");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '6.3.0.6'},
  {'min_ver' : '6.4.0',  'fix_ver' : '6.4.0.10'},
  {'min_ver' : '6.5.0',  'fix_ver' : '6.5.0.5'},
  {'min_ver' : '6.6.0',  'fix_ver' : '6.6.1'}
];

is_ftd_cli = get_kb_item_or_exit("Host/Cisco/Firepower/is_ftd_cli");
if (!is_ftd_cli)
{
  if (report_paranoia < 2)
    audit(AUDIT_PARANOID);
  else
  {
    workarounds = make_list();
    extra = 'Note that Nessus was unable to check for workarounds';
  }
}
else
{
  workarounds = make_list(CISCO_WORKAROUNDS['show_running-config']);
  pat_list = make_list("^\s*http server enable", "^\s*http [0-9.]+ [0-9.]+");
  workaround_params = {'pat':pat_list, 'require_all_patterns':TRUE};
  cmds = make_list('show running-config');
}

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs10748, CSCvt70322',
  'extra'    , extra
);

if (max_index(cmds) > 0)
  reporting['cmds'] = cmds;

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);

