#TRUSTED 9e9aa82c082d4aba0f4b6bff16e4e41babb161cab473d10a2ccba0dbc565343bcbb2a7571bb0a5ff258fb61b1407e43d2d714118de171316a23af7413b427265c66332f4acf8e6d702cce6dbbf740ebdbdb44df461c58763bd3c676eb35c5d079e73fb7f8c1ce4c3de2bbef9e00761191115e8f391dfff4d512da94a1b85ffba8dfa005ed403dcba779915a445227db970eda69d91a80308550bd0634278531851e78d3a8f7bddea1e9118ecff97adc7e6b934fa08edd1b41dd237d17edb664f570a424edd34e236aa0edf50b8dd379e3a69633df2c09dff82bb63499efef5fb0dc84a4c73eeb9a329a60bded17cebf320b5c7f6f4dd77ba0350d9f9915702d675a983e4aa6f1fa220f5f8cd581ed9b131c360efff0fcc27bd7865882c7bd68782f8b317896da5c624e0e8ee805ec482e0a7848db95992b6d7dfa81e55080d020a2c380fb539d84c207d2d24630b5b82a975fe13a6f7e2dfce20c9ef6e5ace3a0fa80a007ddcc6eb1a9eae319025264ce4d96171227d1b80eae3b5d217dcb5cdf5e24800812e075b2bc7c2c3f053b5a264bb24b8197aafe6ea88fb24262290fcd820c1dbd54008910181333b14fde3a932192a10aca2b11c099c6631638989053fe9f7c437e8ccbde7bd244dd15bbd5914f66859d21487985f259aad94a8b4da49890f9326ea55b21197503009fcdd243ac137438049678342dd064a88827248
#TRUST-RSA-SHA256 65e1dc0f728012e1c0d2af5341e8bcc990c6fa7cc807ce08a675fc97a72cd63adbb5faa2ce5f4a73c0c8213721b733a302e10e64a06c07ed605e53282acfc94efc2fc39aea19eb6f5ffc7657576659daea72a2e2d1dc85fcd583326065f59933f000a5454cc47041b09b4699b20d45cac2659fa05b6bcc98b91eec57776cf85efbda025e01f7992705f6476f85d20106264a09f4931bfae9ac037846ad8efc1978bddeb282d920649324195995a7f9291f055576be9ca1c07554c08b2acdf9c711534b38b0c10f59bafa1138c7a191433f6c04c217fda4a92faf7b25bee82c2229ed656f1bb13db59e8cd5b64065f16499ce2bdf91878d8113e2fd612ef2d9e964155e0a4e708654ab5ac65e2199705cc77cfec5a9d030fbdfafacfaa6e8d2df96646e5c444e5ac61602645e74aa6537da6efa0e4e1ba8514495abf0a38c62c922989c89726d523c0c49f024f6444451898ff8996e54f9bdc23c8a22eeb7a8128dd0694a392a98b8ef21e76d5455a4179f1c760ce8cdc530b30713b7f759b9ba6bd63c3910aff21cb9db6d810f42f8566f7f159d6a76da5d13cd86aa3b2efab38dd40f5fa634193c896168c458d74131caae1b1f2479539e697960ddf6c4cf086bf9af5b3e4c834c475e914039080e247cedfa8036da6218fa7b3d231e509d1028b0cd370c5e969852c9a38086b01bccf537ce0461136ab61a4e0b7e99c63937
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165591);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/02");

  script_cve_id("CVE-2022-20847");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz97985");
  script_xref(name:"CISCO-SA", value:"cisco-sa-wlc-dhcp-dos-76pCjPxK");

  script_name(english:"Cisco IOS XE Software Wireless Controller for the Catalyst 9000 Family DHCP Processing DoS (cisco-sa-wlc-dhcp-dos-76pCjPxK)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a denial of service (DoS) vulnerability.
A remote, unauthenticated attacker can send malicious DHCP packets to a device with DHCP TLV caching enabled, causing
the device to reload.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wlc-dhcp-dos-76pCjPxK
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc7e9135");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74745");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz97985");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz97985");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20847");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var model = toupper(product_info.model);

# Vulnerable model list
if (model !~ "C(9300|9400|9500|9800|9800-CL)")
    audit(AUDIT_HOST_NOT, 'affected');

var version_list=make_list(
  '3.11.6E',
  '3.15.1xbS',
  '3.15.2xbS',
  '3.18.9SP',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.1z',
  '16.12.1z1',
  '16.12.1z2',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '16.12.5',
  '16.12.5a',
  '16.12.5b',
  '16.12.6',
  '16.12.6a',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v',
  '17.2.2',
  '17.2.3',
  '17.3.1',
  '17.3.1a',
  '17.3.1w',
  '17.3.1x',
  '17.3.1z',
  '17.3.2',
  '17.3.2a',
  '17.3.3',
  '17.3.3a',
  '17.3.4',
  '17.3.4a',
  '17.3.4b',
  '17.3.4c',
  '17.4.1',
  '17.4.1a',
  '17.4.1b',
  '17.4.1c',
  '17.4.2',
  '17.4.2a',
  '17.5.1',
  '17.5.1a',
  '17.6.1',
  '17.6.1a',
  '17.6.1w',
  '17.6.1x',
  '17.6.1y',
  '17.6.2',
  '17.8.1',
  '17.8.1a'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['dhcp_tlv_caching']
];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCvz97985',
  'cmds'    , make_list('show running-config')

);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
