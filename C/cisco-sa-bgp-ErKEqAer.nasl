#TRUSTED 7c7eb8edba27fe40c3ebca58ed6be8c74cbef9f8da9cfae220b7054281433b125b8f14a2b4687dbd9db0af1bae16549a53a8299818947ae0a40ca016b815dc2d1de885ad6f181132a8b1e3e5f9f7cb921b904d8e066f3d8be91b864a01232479bee44456f965d6cb04eda123e3fbd637e0c7958fc3a63dae036fc77d1ad17e393a7c26d584b576cbebfe1e34f36bf60d78fa3f48b16596e779a2da61c1b60d5ca74a1866fafa277e7eefa52ba11d40dd1ddd47ea733c9b0524eca9d721453d5a371455da1946d902d34edf4689d00275e96779f02d632bf6d9561657ab20f87e157aee2bf1b66143eb4dc2af1c9f4e2fbae62336ea12a3db21dc5ae25ce669019fdf24e013819b2c98abf4ce01ce53866288eeaedf1998b02b544c258c8db0277679841ed26018954a8e94b4b0a5e0dedebbcf7a656a3bcf8de326994f90d8d46a4166bb43d43893593c919fd64baec6b44068c111a621b31284f6f96feaf873a8928abf81bd84804b72e0f83f32c687881a5b2d4cee0e942a0dab374b9ca5095b2ec915fbbe70207565bed5f99ba7e8383ca2e128f4175188b78f2a9b190de9def53d7c7ab3bc2e414e23102bd29c03a343ec0530b7ce26888c13d518047ed145c8d6cab985b12695f7508595eb0cbc22310ae8cfd8fdef9792ad24116cb73b07cee0cf0dc3aedf94d0c73884be1d12ccee52a3072028733d86ab4bc3a60c33
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139577);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/10");

  script_cve_id("CVE-2020-3449");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu54677");
  script_xref(name:"CISCO-SA", value:"cisco-sa-bgp-ErKEqAer");
  script_xref(name:"IAVA", value:"2020-A-0374-S");

  script_name(english:"Cisco IOS XR BGP Additional Paths DoS (cisco-sa-bgp-ErKEqAer)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR Software is affected by a denial of service (DoS) vulnerability 
in its Border Gateway Protocol (BGP) feature due to an incorrect calculation of lexicographical order when displaying 
additional path information. An unauthenticated, remote attacker can exploit this issue, by sending a specific BGP 
update from a BGP neighbour session, to cause a DoS condition on the feature.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-bgp-ErKEqAer
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?52fe83b4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu54677");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu54677");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3449");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(754);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XR');

model = get_kb_item('CISCO/model');
if (empty_or_null(model))
  model = product_info['model'];
model = toupper(model);

smus = make_array();
if ('ASR9K' >< model)
  smus['6.5.3'] = 'AA17486';

vuln_ranges = [
  {'min_ver':'7.1', 'fix_ver':'7.1.2'},
  {'min_ver':'7.2', 'fix_ver':'7.2.1'},
  {'min_ver':'7.3', 'fix_ver':'7.3.1'}
];

workarounds = make_list(CISCO_WORKAROUNDS['bgp_additional_paths']);
params = make_list();

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu54677'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:params,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  smus:smus
);


