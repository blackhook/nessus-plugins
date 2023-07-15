#TRUSTED 46a1cc03980aafa107e40627f9427433c78bc8ddb52ad506fc63595493c4b5a0071740c774992e4262be851b1a0da88950ca6ea4cc5cf24abc9fd4529f21a6bb59e1f514d985f35d4af4e133464e6171476568ed3c0be9e0512875164c56b829a3d9466e954de8e62e9aba480ef27f8eed0abd6bb0f8e1014ba51165df73db2fa1239c52f0f12cc07efa8f03440a75a574f6863b6758cec8fafead0f3faed00198dbb890fe57006e75df9eff57215b11e5b00f106ff8499302848b4a27246fa928b0283c8d798e376a836fd381346f4f086a6cabf349633363cf5d2b780016e85c72192fe95735ba6665b8f670e2bab550453ce271b42aaf07c9f26137bc7f8d827207f0a56a13ed79b5314dbe16b18120d4cc781eac4a65cae210acb73e7400c5fd14e554963d89d3729b02ed723b68f3f36ce9e455bc5f9d764ad7578d917a7e33d4bf5394e77f6f6eb6f22121408523302f15ea3d24d5907955c34978a78fd4bd675c532d0b68dbd8ab942acc2d679ff278f8d69bfa2a4ab8c7213548809859b75aeb25be4251144428dd8a24b9492a9d8ce8ca10650c7494ba4b099b51ba4bdcf6756e9fa58074185becfc487c0911f7104736a3b17aab8e0fb29202e03c4d4d058feca4ee533b3cf61a057f85cf1c8aaf316814ef1e76028748300d0bde5058ebf5eca8406415b9fe92a6a83bcd47a4908b98818ad24a75a1cbb2b5ff8d
#TRUST-RSA-SHA256 74fb933845a728fae2688ed3cddac45fdb89b1234d5afd11f553a48104b037e42c2ee35a6f1d4e299b15519f32af0c62b76eaa762c20eefcffbb2e0716ef6016c340d7a01933df3f8318d5b3281bd775baa5f4444b79c979bbc11ed43b4109b81d8a4b49bdd11c1e0cfcb380cb32e93f46a1aa24e28c96c35de8c16e1345274d00a586886a285ccb6eb845ccfbca77d0abb91ae69915b32dfd6a23b63aab9d9277de7d70e5a441910f60c465e5d7287b88579e99fecec80f515879a45f653c5f7b0571c3dbefd21e4588e486c58aad18181be9d1093a3c609942ca2cbacf777145785588e909b052e5382d6463af1d86373f81e7c81c279ffa8434885bcd2e316a4003d32009e7c60321c6af49fa512fa5fb0fd296bc5fd694bbdbf1056709e2d95431ef75ef83b7e72ba0e4b313e3098563e444e659f85717474548ba9047070effb01f3c52080258215748060a21e5c3de657d81b6b34d71a8684612cc3cc8518c3a4e2530121e41b92302a126c1edda9025287446c55180543ded731de7e96bb839d0e020822439b3c67d1026fedb771eb41fb627583ee55a41b20191ed7ecf399806bad8054c9e67d41e839f4b938e75084cd35dac27f3690ee1842c60561808e16f4699a70343912f170827f83ccac218f7010edf528677ee6ca1bc8d61f3a98c787215a44ae5122bea08842fcf40a6e3d37dfa513fd0895e703dae7d51
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140111);
  script_version("1.29");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2020-3566", "CVE-2020-3569");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr86414");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv54838");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxr-dvmrp-memexh-dSmpdvfz");
  script_xref(name:"IAVA", value:"2020-A-0442-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0114");

  script_name(english:"Cisco IOS XR Software DVMRP Memory Exhaustion Vulnerabilities (cisco-sa-iosxr-dvmrp-memexh-dSmpdvfz)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported configuration, Cisco IOS XR Software is affected by multiple vulnerabilities:

  - Multiple denial of service (DoS) vulnerabilities exist in the Distance Vector Multicast Routing Protocol (DVMRP)
    feature due to insufficient queue management for Internet Group Management Protocol (IGMP) packets. An 
    unauthenticated, remote attacker could exploit this issue by sending crafted IGMP traffic to an affected
    device, to cause memory exhaustion resulting in instability of other processes. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number and configuration.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-dvmrp-memexh-dSmpdvfz
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?44ee1673");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr86414");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv54838");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr86414, CSCvv54838");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3566");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-3569");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['disable_igmp_multicast_routing'];

var model = get_kb_item('CISCO/model');
if (empty_or_null(model))
  model = product_info['model'];
model = toupper(model);

var vuln_ranges = [];

var smus = make_array();

if ('NCS55' >< model)
{
  vuln_ranges = [ {'min_ver':'6.5.2', 'fix_ver':'6.5.3'} ];
  smus['6.5.2'] = 'CSCvv60110';
}
else if ('ASR9K' >< model || model =~ "ASR9[0-9]{3}")
{
  vuln_ranges = [ {'min_ver':'6.1.4', 'fix_ver':'7.1.3'} ];
  smus['6.1.4'] = 'CSCvv60110';
  smus['6.2.3'] = 'CSCvv60110';
  smus['6.3.3'] = 'CSCvv60110';
  smus['6.4.2'] = 'CSCvv60110';
  smus['6.5.3'] = 'CSCvv60110';
  smus['6.6.2'] = 'CSCvv60110';
  smus['6.6.3'] = 'CSCvv54838';
  smus['7.0.2'] = 'CSCvv54838';
  smus['7.1.15'] = 'CSCvv54838';
  smus['7.1.2'] = 'CSCvv54838';
}
else if ('CRS' >< model)
{
  vuln_ranges = [ {'min_ver':'6.1.4', 'fix_ver':'6.4.4'} ];
  smus['6.1.4'] = 'CSCvv60110';
  smus['6.4.2'] = 'CSCvv60110';
  smus['6.4.3'] = 'CSCvv60110';
}

var reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr86414, CSCvv54838',
  'fix'      , 'See vendor advisory',
  'cmds'     , make_list('show igmp interface')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  workarounds:workarounds,
  workaround_params:workaround_params,
  vuln_ranges:vuln_ranges,
  smus:smus
);


