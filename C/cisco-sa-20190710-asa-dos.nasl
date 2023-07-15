#TRUSTED 905c7ac3476c4d8846df6a3150971aded585476821f1387ca811df315cc41c54dc8f191e57c609f6f3b5a7067fbef5c03dec3771587371beb1085e5252acdfab3fce2d4751394bcbf506d3cb105e7dc01e2de40689f34e394ab6bffa3072252e6afd3d85fc5bfec5c6f3ce09f1b0f8c8c2546429477e36c6f96cec24c7940d28a7cc87a465db8d9e2359bb622b9694f4e0baf7ae14910b260d8328fbe61529a4dd3d9c2885d6f739f24fea1b4e61d1bce5990ba193908b20d68a31179d3b13aa45db4e66a7003f592a7fa7f2b631b72459578fb0651abf187d5f1b1455fab42aee821c4ba5e7b3bbcf61898d51fe43c0c52801dc014b9ec780bdb75eeacbd4f8b5bef798026897ebacbc7b281ce89d42538efc3f192570fef679bd2e6103215c36f8f43be954fd9e4caf8e8d608c5606f5dd7e34c2e4e11a344f9b7836fe0da2686a9056e8656d8804c6754bae90b2dade79e18a119dd65c7a5f45ca55091ec0074bc73704c281f857e2b490c17209d1c0cc3cb08c93651ec4150dd231319295cd9d313320bee2f6e2cb10dbf184bf327684a1c378ade1839b1771062e9e992e77241719086f859bdb236d2ca9ffc12987ccca5f5b8bf4d22e3accd4f07acfb5a80e7ab5a62cc171b0c615670567fb8e600fe58baea253e6db4f89f517c099f31fac5030a9c51a91e19b6c5a2f86b752df0c8a7cb21b4ca1db1ae6883ff348e1
#TRUST-RSA-SHA256 79dcf40d0eb5a9f027444007c98f3c9c0e0b1f27f81f7c9281af878bc6bb2d9bb74b6c75ca40e8cad9bd12e2ffbe915cbc85c2ed984d7e5325dbc4eafff7a529bc8dffc616d4bb7431db0f1cc12418f7103327d92a4bae791f22014a6401cfe29136934dc6c12f09ca8b7580a307088f91c742216a4f07a11678a7b7dda0ebc1388b11374121a6eaf5225b4c9cfdd97a9775166bdee2a8d457c30a848580aa7e552c5242bae11b4806728f1773ccdc1276f02283910dbd32df12d829ee5a8784b4ac6b74cc26d6de79c5af0e1ec26e57aef79fa5c2112856180569d44ef4ab5703b09bd526997d3792dc96c66b7aa58e52738056f25d8edcb37f684a81443c3a2ae1d224fe15ef9136b8ec3b0ac3d3be4a7ad376e284bafe2ddbacd01ca42b9f7f2da2561eb8aa314a28384ed274036ebd52491721f6ce313c91dd207d67a44ca4974551cb556312408d8cff570bf87addc9e3009f5cccc9f5299b74ba4a4bb3336414b31d050d6917fa1ee4f13dbcbcc926e201b3020a0e67878b741b2170a40c7d888a1ebcffe7b21642a57f5c9102fb595ec0352e39057177fca71b51b04016ed6a0581a15d357fffeee1718257cfe2154f35d4f80a0f2d6f2b2a8e5faa8abd73f675f634e3153cd6e55016b9e467ef45f729a3ce41a0cdab4f787cc1ba8e206a197a4a9b0c5a488a2258b91168096ae902b1a1905ea9d2285612671ff92b
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133043);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2019-1873");
  script_bugtraq_id(109123);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp36425");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190710-asa-ftd-dos");
  script_xref(name:"IAVA", value:"2019-A-0271-S");

  script_name(english:"Cisco ASA Software Cryptographic TLS and SSL Driver Denial of Service Vulnerability (cisco-sa-20190710-asa-ftd-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Adaptive Security Appliance Software is affected by a vulnerability in the
cryptographic driver due to incomplete input validation of a Secure Sockets Layer (SSL) or Transport Layer Security
(TLS) ingress packet header. An unauthenticated, remote attacker can exploit this, by sending a crafted TLS/SSL packet
to an interface on the targeted device to cause the device to reboot unexpectedly.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190710-asa-ftd-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5001de6f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp36425");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1873");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/17");

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

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

model = product_info['model'];
if (model !~ '^55(06|06W|06H|08|16)-X')
  audit(AUDIT_HOST_NOT, 'an affected Cisco ASA product');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '9.4.4.36'},
  {'min_ver' : '9.5',  'fix_ver' : '9.6.4.29'},
  {'min_ver' : '9.7',  'fix_ver' : '9.8.4.3'},
  {'min_ver' : '9.9',  'fix_ver' : '9.9.2.52'},
  {'min_ver' : '9.10',  'fix_ver' : '9.10.1.22'},
  {'min_ver' : '9.11',  'fix_ver' : '9.12.2'}
];

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['asa_ssl_tls'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvp36425',
  'cmds'     , make_list('show asp table socket')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
