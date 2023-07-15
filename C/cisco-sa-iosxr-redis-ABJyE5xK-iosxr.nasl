#TRUSTED 246b9e3a0a6b12a8f175c4a45806857be899becc0ee1270e6c7be3640d18d582b9b32db30d8cc99f5b0c68b9ee6b93170949a7382ec8a151451e160bd70ec8b74e9731b04b8778c2032ae4484e5857360258896f0012c52ec7234c995546ac850527585077a18a6d67dc015128ad6eb84099c5d75e492bfbd4a70547830bb1ef4c7b8aef9495dd730ea6561658a2fa1f47a0f619de107104f32c6d6a10cf10e62b5d294f7ab1ae9ea10faf7da3aebc52387603e550b25f2ba0bd34e9c92261100720d17c23c9228bed5eab84e536f123e69dc3b3ad308a6dfd012f62de1a23ebdc9aac6036c37df6916d47b8bb6c35acf318e586ebf2350f42a563bc6f146fc77171ab42acd02a433a8f2ecf3e7dbca34797e308414666107e4365ec376c171d3c66eaa31669b958e51846dd8e6dd64ff8dc99eb9ea36b33b8668daed545c13c9333204e15c230002cba41da731cb7e4e3ab211a6c434a5ecb1c030c1249d15aa177369c608a6d90323cffe0beb19cd54fafeac48b4404833aa523624ccb4662a0bff55d88fe93b129e8909c3ca63b74199927d4cf4242056de30368e73e19b492dde33353875478296a94b58dd7c23e6c3157d3a71c4994ed57a5edf68c4c1e58fe20bc1d959df4201b2d503c79a1aa8fa84ed055670131469b2d36572601a46a50434b48acd4c856aa4dee89039804ad0c6913e7f88e6d8a55c9c216fe9f83
#TRUST-RSA-SHA256 2d64c6dd4a771b41f622ff05805c1d09f7db3468b825ee0ae1c93ab258d3488f389eccae45fa2b1b0ae4d69ca8ab8330b2fa1b6037cc2a0ad943125d25b7c04d3f3adf11e69da1e5a28c006d74eb81878753f4b518b50ab70cf22ae94c4abcbb5c58f8a0025e0952887299a23586af4b71ad37bd391c107d69b451f16e3ef0f8767fffee5f0d23179eaccdc30609bcfad85833a4468c837b190f5198697c0a5231a078e0c2b6d0324b45de2a0b59dbfd49b99d25ddc54e6697ebbf59beccb6a89b239b551b0b33bae35536edc410170f38f0884b318fba411fe8e43e4dbbb05cffd19b2fa2f993eba32d4cd4b3e9f899bf64cdec271463dbcff236d38da928200ef2107e2d21fcb219e61402fcbf43fb9a5d319fa2d8cf89632d14983b93d558d50990307d2c218644ad6b95c4c2424060f2c4aed3560aaf595d522e915f0659fad406db04f38a3eeeac251e0f8b1a1bd05e475031f7ad315d292560cd4fb21f5e575b890363d1be939611c495bfdef3b49589db025f6131d5012bba04d1fc90f7fb8c18a43379b87b1e25323ea374c51dc64d8eb4d28ff0865a14897f60e65134cd0d749a83bddef280ae75aac05c20c00eb97e1ece63efb6b2e9a494ad64ef6629265a9154cce381f910513c4ab23a869001d86156e94e96497afa18802d4482873dc05520febed1f8472654264e75b120ffd72470498d2ee793d39110f999
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161524);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2022-20821");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb82689");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxr-redis-ABJyE5xK");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");

  script_name(english:"Cisco IOS XR Software Health Check Open Port (cisco-sa-iosxr-redis-ABJyE5xK)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by a vulnerability in the health check RPM due to a
port that is open by default. An unauthenticated, remote attacker can exploit this, by connecting to the Redis instance
on the open port, in order to read and write information.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-redis-ABJyE5xK
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf613032");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb82689");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwb82689");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20821");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Host/Cisco/IOS-XR/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var bug_id = 'CSCwb82689';
var product_info = cisco::get_product_info(name:'Cisco IOS XR');
if (product_info.model !~ "8([0-9]{3}|K)")
  audit(AUDIT_HOST_NOT, 'an affected model');

var smus = make_array();
smus['7.3.3'] = bug_id;

var vuln_ranges = [
 {'min_ver': '7.3.3', 'fix_ver': '7.3.4'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['run_docker_ps'];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , bug_id
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  smus:smus
);
