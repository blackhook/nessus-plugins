#TRUSTED 2c775646c33e624180a966789f74ae1bf891ac0bb7d92bc45c863597ed14e6b833ab6d42e0c4701a756cb38eea2879900143806e3fc0d9523fd9660fa1d780699c02eaa2c5cd067afeefa3c0a3b13581eb862fdb48ec51acfc085b26de9c54ae8f4d00621ca3291aa94f2cd2e87c1875720252dba8d0e00049a8f855a6aeb1e3f4873fa17908d35a0774eb0ceea59b96ea235252658d233862ffad0598824586de341762b9f2ae3fc4f508ed27048550e4e410ef51bf4aae287b37bb86c08e1858cf82b74186290885147bff94a697a9cf84f193dcbf7c963d89d36e5b185243f0c7b7fd661c9ebe6ea2cff67af0bba4ef0859b68154c01a7179f7755c23196905cee842c8ef720bd11b3f0e02512fb350cc051663623cbd39bfb772f5cb83c0e18405daf04d98fef4af3c86006425c4c48329868f43dd0873d0f2ef420dda9b7307d2240be52bab4ffaaf517af1a27ae3982f7467d1a7c47fb9f3d88c88893b9bef5ce86fddef9d51dc19fc029ce12045974366a4ede81fca0776a7fba9d49149f80e940b21c9077b7af5b417f67f18b6a1cd05f180eaa3d314372f893d1d1dc9f7e2ff249b3559fc3af67e7b5a09facd77a008d0da43f604fe14b9141dec65c38f35a525e9e64770476507d5751dabd250d8af6bce79fcc13263a0b4d5890a0c0a514d19d697037f3602c69e760d611b6c0380367ee0b447e1e6ee7c26c218
#TRUST-RSA-SHA256 66264fef4a8b01d0458b379203b7ac3fef3e77b9acf1cab5b05a9df32fea2e0017c4406a14df080a5f480ee04a018cae5237da708adea5b3b6a3846e847d39ed47abc7360a3c1d7fb2cbc98936e598e706b14c277ef9a1e5e3b0c56b62ee8c98735dd723d38db9e5162e70b24fb13c79f518ce097dc9b58129b00fe0161fef0375c57c5b199df12e35fdb587d7a8e1bc7db4d2cf2fb948327b3edc3a33eb2dcc5e1edee02f4da50cf5d87aef7d8a2e7a85d27e7c541fc4cee72edff2839a195fee87765a3b38acf8677c6a821658bfacaf231186753e5404cf28364ebc6686c223d24541e8d36b9723cb31bfffe79bcfbfe867181e42e8fd4b8c51cb829aeccb62cabe1810e15d42110de2663e34aaab5cfcba5059890871cfa3b530ee7ac951a1245a8a23a556305d1f32e2f63328ad825a15688b9b45bc797f6d95e9ebd5013fe8abb5feb16cf8bf77a136ff0ddb1b137ae16730a42786df0d9a49b13af7e109652870b3ba718b320f7add9f8896d65b042571e2013bb4e36f05a7ab47bec22cbb1b040987a0960d00f048114ada8bbe3789718fb3ce13618b82da23dbebe7938e214f1865b6eb80c40bde8bcbaf4b5c139fb0fde02916570763478d44cdbee897ef48682a928a80b7e59a8cce506ebcc32a277ab138a795fab3e46401e4c0a3373f8a6d0773918c945e1c32b679a029de83a04b21d05cf3e88aad7c50f2e4
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137406);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3255");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo80853");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-dos-N2vQZASR");
  script_xref(name:"IAVA", value:"2020-A-0205-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0042");

  script_name(english:"Cisco Firepower Threat Defense Software Packet Flood DoS (cisco-sa-ftd-dos-N2vQZASR)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense (FTD) Software is affected by a denial of
service (DoS) vulnerability in the packet processing functionality due to inefficient memory management. An
unauthenticated, remote attacker can exploit this vulnerability by sending a high rate of IPv4 or IPv6 traffic through
an affected device to cause a memory exhaustion condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-dos-N2vQZASR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?428b34c6");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73830");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo80853");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo80853");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3255");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/17");

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
  {'min_ver' : '0.0', 'fix_ver' : '6.2.3.16'},
  {'min_ver' : '6.3.0', 'fix_ver' : '6.3.0.6'},
  {'min_ver' : '6.4.0', 'fix_ver' : '6.4.0.9'}
];

# Indicates that we've authenticated to an FTD CLI. Required for workaround check, set in
# ssh_get_info2_cisco_firepower.inc. This should always be present.
is_ftd_cli = get_kb_item_or_exit("Host/Cisco/Firepower/is_ftd_cli");
# Indicates that we've successfully run "rpm -qa --last" in expert mode to get the list of applied hotfixes.
expert = get_kb_item("Host/Cisco/FTD_CLI/1/expert");

# This plugin needs both a workaround and hotfix check. If we can't check either of them, require paranoia to run.
if (!is_ftd_cli || !expert)
{
  if (report_paranoia < 2)
    audit(AUDIT_PARANOID);
}

# Don't set workarounds or hotfixes if we can't check for these.
if (!is_ftd_cli)
{
    workarounds = make_list();
    workaround_params = make_list();
    extra = 'Note that Nessus was unable to check for workarounds or hotfixes';
}
else
{
  # Workarounds can be checked with just the FTD CLI
  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  workaround_params = WORKAROUND_CONFIG['ftd_block_action'];
  cmds = make_list('show access-control-config');
  # To check hotfixes, Host/Cisco/FTD_CLI/1/expert should be set to 1
  if (expert)
  {
    # Advisory does not specify "and later" for these hotfixes, so ver_compare is FALSE
    hotfixes['6.2.3'] = {'hotfix' : 'Hotfix_DT-6.2.3.16-3', 'ver_compare' : FALSE};
    hotfixes['6.3.0'] = {'hotfix' : 'Hotfix_AO-6.3.0.6-2',  'ver_compare' : FALSE};
  }
  else
    extra = 'Note that Nessus was unable to check for hotfixes';
}

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvo80853',
  'fix'      , 'See vendor advisory',
  'extra'    , extra
);

if (max_index(cmds) > 0)
  reporting['cmds'] = cmds;

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  firepower_hotfixes:hotfixes,
  workarounds:workarounds,
  workaround_params:workaround_params
);
