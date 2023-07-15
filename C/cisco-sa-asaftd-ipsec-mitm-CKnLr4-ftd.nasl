#TRUSTED 60e0426ae4c8b9f514cd0f509c383d5699e5f1df433e8928b696a15bbe79feccd5a2ea33bd7074e52e4423d74bf5ad237c7d7d808f94040d38e8b4aaae52a6618f53d5544abd8a6ab1d7e32cb8656513be11d5802269992617a87b1ef039d323ef0f8bd22fae0269a578e559e09d2a3ebba1cdad9acf1594443928b5b9f49a55d2ad2d0e1ccfd8e275027488d58f6c213dc339e58d5db6efe6abc4cd18be0e1a74ec8354c33dc48e70c92bb2d7b870d61008d9354a945dea96fd3bdfd34bbd681507e06e1302cd20842e0d4bb998f392f97e841a68c8614d30ccf363a472ab0c8b54c86322656b35a3e0f8c91b124cb78bd8fd7e063dc5163c684c7eea0a3e5bfbbc21f18e075ac55078670f8b01486eac152f47dfcc74f9346c93737fda02c5c59322424b7d5d50b61c383fc68523b75c38b7e61203dd83de5db390c5b077c33d9b493507a393256fc70055f252cbe5bd59544c2c6170155a2dc7060d7686bcf981a4cc6aff8e9d6ecfe33d632f5d917eaad99481bb5aff3f1260ab938b371932213218db742c1fbef7bb1d12094971d3d2962494b1aed1e8a76138f11a5a23eaa206557c9f5d48ebd86dbaa05a238035eae6f6eed45037e66ed8385300ac97a4c5ba541c6b33b4077de3f793b8bd5a211753734a90e7cfd8e52b7d686d571363e7e7db8760bf3a819df9b216057e2339c83f72a6acbca1f09557fd61f46dd3
#TRUST-RSA-SHA256 9c0e7e31b34c5067e4c05e6caaa1d5abe13d512c1360864d7f350eff5dbd59c35f799689b7f622fdc225e097e26834c64cbfb29de2b6321b9c59f35df43a38f93b3c2f819a37e1dc9dbf06bd054508d43b11ad00ea5aabd600ca10e31509a6c7e49a933a6c27bae355b4c51f0ed39e98b8a5138bae80ee53b54a0dfa04fd5d0a648be2c041fc81c4ea2d02183811601e62cc5f37470536303dd0d5b976dee22d89d3503c6d44c098077c3d7d276be8aeb6bd9b932c4bf2fbc139aebf163bc30b3d311b8b1fb88fdbc1c98674f3ec361773bebb54f9eb50ed5d8063ac69aa2a52a4fec5306c96b5722a8ff7dd41c7759cda6a30d62f611bc647ad9b0d04a5960c9052cab66fd9ae73a11cf6b8fd73d4639d60cdc71fe27614e6bbde0dd7e42676392f8e6b3eddb698019a63e8e77b5db6333e30c70c1b089cc8773f852f93f3c23a36a5b7202476673927d0108b2403f1041a4fe3060d684bbeb1c254e7bb790ef2868ecddf095b58c57deaf7513d83902ba7f3555fdce841a0fcd0cfc19021edd7cb1c78d8d3dbcc34f744508c67eaea44344caa01cfaf529579149e4a1502aceefff960cb1454ef4d4f22f4c60fc575147366f030c33ad580cdb7fb362c83f35dcde2bffce0df8890cf22bcf46585c1e96cea12cc28adf658d1b917df836b107b394703ffcf00f912bde1d7faee4622bb1aee9ee4b6b110e65fb65fdd133c7d
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160890);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2022-20742");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz81480");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-ipsec-mitm-CKnLr4");
  script_xref(name:"IAVA", value:"2022-A-0185-S");

  script_name(english:"Cisco Firepower Threat Defense Software IPsec IKEv2 VPN Information Disclosure (cisco-sa-asaftd-ipsec-mitm-CKnLr4)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FTD Software is affected by a vulnerability due to an improper
implementation of Galois/Counter Mode (GCM) ciphers. An unauthenticated, remote attacker can, by intercepting
a sufficient number of encrypted messages from the affected device, use cryptanalytic techniques to break the
encryption.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ipsec-mitm-CKnLr4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1bfd62ea");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74836");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz81480");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz81480");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20742");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(325);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var model = product_info.model;

if (model =~ '9300')
{
  # Only some versions of the 9300 security module are vulnerable
  # and we don't have a way to differentiate
  if (report_paranoia < 2)
    audit(AUDIT_PARANOID);
}
else if (model !~ "4(112|115|125|145)")
  audit(AUDIT_HOST_NOT, 'an affected model');


var firepower_hotfixes;
var extra;
var fix;
var workarounds;
var workaraound_params;

if (!get_kb_item_or_exit("Host/Cisco/Firepower/is_ftd_cli"))
{
  if (report_paranoia < 2)
    audit(AUDIT_PARANOID);
  extra = "Note that Nessus was unable to check for configuration or hotfixes";
}
else
{
  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  workaround_params = [
    WORKAROUND_CONFIG['anyconnect_client_services'],
    WORKAROUND_CONFIG['ipsec_gcm'],
    {'require_all_generic_workarounds': TRUE}
  ];

  if (product_info.version =~ "6\.7\.0")
  {
    if (!get_kb_item("Host/Cisco/FTD_CLI/1/expert"))
    {
      if (report_paranoia < 2)
        audit(AUDIT_PARANOID);
      extra = 'Note that Nessus was unable to check for hotfixes';
    }
    else
      firepower_hotfixes = {'6.7.0': {'hotfix': 'Hotfix_AA-6.7.0.4-2', 'ver_compare': FALSE}};
    fix = 'See vendor advisory';
  }
}

var vuln_ranges = [
  {'min_ver': '6.4.0', 'fix_ver': '6.4.0.13'},
  {'min_ver': '6.5.0', 'fix_ver': '6.6.5.1'},
  {'min_ver': '6.7.0', 'fix_ver': '6.7.0.4'},
  {'min_ver': '7.0.0', 'fix_ver': '7.0.2'}
];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCvz81480',
  'cmds'    , ['show running-config'],
  'fix'     , fix,
  'extra'   , extra
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  firepower_hotfixes:firepower_hotfixes
);
