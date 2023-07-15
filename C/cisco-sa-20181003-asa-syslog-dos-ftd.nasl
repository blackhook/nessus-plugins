#TRUSTED 4cb7c72ef75580cc89966acea5df02b9d76386975b5615040f2648b0ef00c9388aee536610388f9ee532c4ee630cf612bec90d64c77fb66a8df0dd4bbd487a4a244adf34212065892e04c362268b6bdcb6afaada6c4893b32e29ab4395ade88756c9419d1986be00ff9f10f940f6ed6a85525d09ac1b557b707c10ca5dfb35fdb23b7c7fcd744b392f407f5543fd19c380d1002c47bc2bc744cc0dedde3f798eee8c93f5f04dba00eadafb76c4ac0ad59cc69a7d1b59bd288b2bff17abf544aa7de7b148b4d461d34f32177d7b2bd150ec67d6e6a5eeb1d196f343c18a39d613a5c6500709555dac002d5ce80ba6ca0a2802027fb1fa1993d6b1c1eee8537c81ae08508c8f243aa8f5cf0a6896901839304f8068b99f4062343fe9cfd81eea6c503a98761203471bcdbc53e02188c86bcf2a8fc09f146eccaf0a09e2c51cc8b06e574c202f139de3f52ffbfb5d3235362614bc9d98eeb5faa8ab4867153988ebd974f5867455063a8d08448be6b043a813d3a5033e240866689ddf169a1113ad9f413a81d9f37538db382ae774478276c7f307f602928c7ac949d4af41e2338115dd76b9453186847e5a5e3e5fe78509c918fb769602d52dc66a3d930fe16a7e43d9da457b7e9fd444c0ab906922a31730c2a649e93c64cb038a534cd1adb135ce5b3390e7335c465689967bbaad2447c8c1a9b151141600ea747ebef10b1ef6
#TRUST-RSA-SHA256 8c9921b97b54b0bc40211f81c530342dde1e70833bdd695091a8f227acb04b307f8c976d463cf987300b5c57baf405e11a4580fc0396e689a73471d034cc2b3168966dac2b8f61b93882e0e887e7cbe8204bf4d0a8b32a56986d65c611bae00405d5dd5ebb0ba0a0f15026d16bce22f23c30633c57c73041cdadc42ccd6ee34bcef451d5ff18ddf11b23b5ab8889b2568785de13ef8eb28abc8062ce6807a535174a6bf363864c21adbdf94f2558fe68a10b9151c69bdd42cd305e48a27a3b26277abc343df770a32d5cc142465309cc460c181beb80548c98677d093ac497344041c42009333dacd7549ee0129ad4ae11ac1bec265d2fa64b5a6a78d4e719d8457d0590b22e8147b02a670ec11f22963a95d1163421621b7a60cb9719273b11fb71a41cefc2b3a93c5ab074c524fa47a9bc2f5b460bdf04cc873bb1fcf3fa2d52154400bee35aefe37aad361563869fa2252b547ed193eaf5cc6625428ad102c9c4beda5bff6c38fbbdb4fe1970fe9dd714736f589452ec4064718f3ed22fd983ac08441f4da7950fdccefe012c4a4a8f456d4d9fe3921af6f81c4d5c41e5e77b399ca22793f95424e885785d406577feb6520bd55e475816de5c2845a84d3df3e0d742f1c045d8a353e4a73080b63c26c4c891d6493b200d07a8812f2f29c71be057fc887300b9a5d057936d6ab70a25a947ee7ca83590bddb176fee431adb
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133089);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2018-15399");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh73829");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20181003-asa-syslog-dos");
  script_xref(name:"IAVA", value:"2019-A-0271-S");

  script_name(english:"Cisco Firepower Threat Defense Software DoS (cisco-sa-20181003-asa-syslog-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the TCP syslog module of Cisco Firepower Threat Defense (FTD) Software allows
an unauthenticated, remote attacker to exhaust the 1550-byte buffers on an affected device, resulting in a denial of
service (DoS) condition. The vulnerability is due to a missing boundary check in an internal function. An attacker can
exploit this vulnerability by establishing a man-in-the-middle position between an affected device and its configured
TCP syslog server and then maliciously modifying the TCP header in segments that are sent from the syslog server to the
affected device. A successful exploit could allow the attacker to exhaust buffer on the affected device and cause all
TCP-based features to stop functioning, resulting in a DoS condition. The affected TCP-based features include AnyConnect
SSL VPN, clientless SSL VPN, and management connections such as Secure Shell (SSH), Telnet, and HTTPS.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181003-asa-syslog-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6fd359b3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh73829");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvh73829");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15399");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl", "cisco_asa_firepower_version.nasl", "cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = "Cisco Firepower Threat Defense";

# Based on the advisory, it seems we're looking only for FTD and not FXOS
app_info = vcf::get_app_info(app:app);
product_info = make_array('model' , app_info['Model'], 'version' , app_info['version'], 'name', 'Cisco Firepower Threat Defense');

if (product_info['model'] !~ '^55(06|08|16)-X')
  audit(AUDIT_HOST_NOT, 'an affected Cisco FTD product');

vuln_ranges = [
  {'min_ver' : '6.2',  'fix_ver' : '6.2.3.2'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvh73829'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
