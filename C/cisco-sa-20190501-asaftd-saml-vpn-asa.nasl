#TRUSTED 7e0dbf02528a0ed145bb0890f2abbaed218bda7561e67fe95a263fa2fb417819033bcf34bbb17c93bae87003d07ecdc88376cc1d1ce5e866ffd52cb0ad46942d64223de78a0564075c2f92aa8174e50f76214a2149358a5768851cacd71065796a768437ce5f2358fcf2f8891da83ea26e34cdb9fbbbf0aeec02ba4a8e985d114992dcd63c4894039c860175cb3e241af186e9725544b2e99ba7477299ff8399d55ad5988166ed0fee8cc37c77967d2863410e688628c0b3d0218536c62be6414b3e7645330b26d181dbb918bc3a98a815dde41f609e333fbdc94157bce960267063f57fbed1b31980f24d7354808886741dd0350416517161a997b2e6171ffc160f6e6a871283f433e98f0194b75f34593f214bac1ab9c4d29bd4303e6852b4d7606905daa78254c5fade888d3b75e21b90b47719a183c2ea961419e8b80c7afffed3bcade0ebf4788248d7a44a2f850dc63a1e8d672b0cdf61a5250a761c7165cff0016d051c42b41ccc1163307f5d3ad64a71d53c1cfba6ab64f1d234bdcd366c13685b00d71474706a295171fbd0f1d1c15e3d8e10c40bded6add82b3b388cc20fa5b3bbd36c17fb1f3ef4b0956c90b99acc3364981132be920a87748c359f1412eef003b68462b786781ef10d8d6c5ba943edcefd11581518c9987358e706c69be50b2de634b1679bee898f0430629bec3f0e7e51a7fc8d33752ed71867
#TRUST-RSA-SHA256 74ada2e486ac44ee7b0a3fed62182e1ee31bc352dc7e0b615b5bba0ae84d66602c285371920e013988a5fbe7e15faa3b7fb78169869b5634a170526acfefbc96de1cf47f9ef9e9148205269a2c8fde202790047c55f24c5d64365b1506a4f0825ca71bd512b0877dd622d0e6462ea87d213ab9365500af81abf7be64ded8ace27b2345245d6d6d1bebcd4d48cff7502d987bc967535bdbb08dc660c14a5704bb7f7ebc870d66fc0ef8ce6039ff1920a21db96025ce1f0dc89f9ed2cf1fc68df0285b3a0e86e8333fdbaa510c94d6c62b3fef331f080616913996fec2aa3167b883bfdde81140607f4bed22ee8fce06939b938d6dabc71e06236d383883da47d752bee8215e7bee77c441a5970f9e40ee3aa33e186a63544b4b3e9995e75397a4e75ae1ed7d748caaa317ffd129209f4d4e5460a94399cb5b9b82710d20173472f70cb47c8bf78b14a96455bb8df808957c0dc0989e2011f6960ffecc8a9c892f6526e298fc7e8b0b09a643721bc21d3009a9603e9381f081662d8a78ec27eeca87ecf7dd4302ba6a1e292839e2d5f0d1980aa2ecad5e1c4cab72caa60361e36ede18cd453e173d3821ebcf0dd27c692f14e59883091c01b286e8557c2e04f1cd10362994ac3eb41c7f7a1354906ce1c7b53fdaa9eab0893bd838b45ee05a1668f9505933fe6080fd60a3b8c4d3475f573f8ee502f081029930359d2afd3c029d
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(128063);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2019-1714");
  script_bugtraq_id(108185);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn72570");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190501-asaftd-saml-vpn");
  script_xref(name:"IAVA", value:"2019-A-0271-S");

  script_name(english:"Cisco Adaptive Security Appliance VPN SAML Authentication Bypass Vulnerability (cisco-sa-20190501-asaftd-saml-vpn)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version the Cisco Adaptive Security
Appliance (ASA) software running on the remote device is affected by
an authentication bypass vulnerability in the implementation of
Security Assertion Markup Language (SAML) 2.0 Single Sign-On (SSO)
for Clientless SSL VPN (WebVPN) and AnyConnect Remote Access VPN.
The vulnerability is due to improper credential management when using
NT LAN Manager (NTLM) or basic authentication. An attacker could
exploit this vulnerability by opening a VPN session to an affected
device after another VPN user has successfully authenticated to the
affected device via SAML SSO. A successful exploit could allow the
attacker to connect to secured networks behind the affected device.
(CVE-2019-1714)

Please see the included Cisco BID and Cisco Security Advisory for
more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190501-asaftd-saml-vpn
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4bb85a40");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn72570");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvn72570.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1714");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(255);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

if (report_paranoia < 2) 
  audit(AUDIT_PARANOID);

var product_info = cisco::get_product_info(name:"Cisco Adaptive Security Appliance (ASA) Software");

if (
  product_info.model !~ '^30[0-9][0-9]($|[^0-9])' && # 3000 ISA
  product_info.model !~ '^55[0-9][0-9]-X' && # 5500-X
  product_info.model !~ '^65[0-9][0-9]($|[^0-9])' && # 6500
  product_info.model !~ '^76[0-9][0-9]($|[^0-9])' && # 7600
  product_info.model != 'v' &&                       # ASAv
  product_info.model !~ '^21[0-9][0-9]($|[^0-9])' && # Firepower 2100 SSA
  product_info.model !~ '^41[0-9][0-9]($|[^0-9])' && # Firepower 4100 SSA
  product_info.model !~ '^93[0-9][0-9]($|[^0-9])'    # Firepower 9300 ASA
) audit(AUDIT_HOST_NOT, "an affected Cisco ASA product");

var vuln_ranges = [
  {'min_ver' : '9.7',  'fix_ver' : '9.8(4)'},
  {'min_ver' : '9.8',  'fix_ver' : '9.8(4)'},
  {'min_ver' : '9.9',  'fix_ver' : '9.9(2.50)'},
  {'min_ver' : '9.10',  'fix_ver' : '9.10(1.17)'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['show_webvpn_saml_idp'];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvn72570',
  'cmds'     , make_list('show webvpn saml idp')
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_ranges:vuln_ranges
);
