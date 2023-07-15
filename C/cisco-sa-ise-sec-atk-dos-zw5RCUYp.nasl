#TRUSTED 658903461378c7f60e7ae27de1a5fa27ac697345b00e60abb8a01965820bb370a2b27fbd4f01a9d2cc9369bbeed54e9168ebf53e2747ac7ddc182b4eacce32a373610e5d95e19e7b1d2d254973556f68d88e36600833c89d153423c9bcdcba990a4e52646c5a1c976a92964e8c958d57906ca1de79a35c57919bdfcb5e7f23eecf44bb3f80c136bd504e61c04ea70974fab646ed88924e402e5ad5bd290db2ac51384ff0d37f18ddef2984c406c7bd8858c27aeb80ee9804c39d901c25e032500424db9fd6f5a32090d1df5a8a9a2e09189433f02c0c66615e6b765c70519f7c779212089dd8191cccf788c89fdd4adbf986cb5980c9a511df26d8a4cd41d33c3b935709bedbd104b1b09b4894b8e98a3b0c007783442b1ce5a8903dfe4ac5507e2a5d377751c9e8e7d679707016b25b079fea559ce2945ca250f323f850c08ded5abe2ce0f305ab2f5bf01206b343e64d68b89eb82b08c7f89a9c6f3f46608c04940db3a0ac7fb1aaf92f4ac5abce5b450e1ef7d3e5c0dde7b33dbdcf3aeb8daf8f728bd3ce09c39d50ea145e89f35fe892201d65b2ad043dcfbc831763b97f4414e738f1c1757bbdf6dd7d8f20c449c8db9717a2a082842c749bceca2bfbb3042a3c76261ef9f3e5efbcd02390f2717a58e17300595091fe4c1dbfd3c93b8982e96ab85818af3462e5868aad561b771d659823238f9cbade8945a58653ad69
#TRUST-RSA-SHA256 75b23e5827752ba7c4b31b441b09febda8698f38236c5619e337867211d4c6d72b1f3c986157566344a7fdfb6165d875d9b4a897f18b9c0a24cc4788d4b70038ffe9a5aab3d2fa900a82f743fa176c902871a4d6916116d49b0b6a417e0871a5b9c3e2552aead42cd87d5cdbfbf84ef6979630d38557feeb7acb3165c7bcf94c1e54eddb37fa9c3f6e29f9529a28b9d4f06dcae50251dad508abb39f818300d64068312c1f48c1d31d06942a55ee098d669d398d56a5cea91cea9575af18ae020a32c7a5d07ecc275943330eb2ba45aa57e7d78f02ae1f116fa26b561b1e3d1214e0e45ad390d7f2778d09e17f6c20684d18a6269d737a2bbbd648323c12fabd94aaaebc501be9afe4229e4a742fbb622d3a058cad4d9a468f31564702fe3362d6221965eb7440041b0ab4dfce57e38abb255af994a466f3e803087d37b45a1f450bfc493a62630c43d32809ef66c0f69761766f9b1db82ab60437da215696df4ff4d31b2655e4a4276a32ed4a63c0d20c76c2ba995a8247ba21b92df4dff684ce33bb6290ba20656c8ced231802310ecec3e5e443d3d21d82db7f9daac69bd23bfec1d8f9f3efd0894751ea285367770f971f5311e616fa13ddcb8f3c4e4ac27eaf3efd79ba1b6a799af1e58dc42242ade5968bcb7cda59f9c3ec687299fa72ed924b771afb8a7497d824f4f2b7fdac01ed9a7f87d62c0e89d10fb56fa6350e
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166916);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/04");

  script_cve_id("CVE-2022-20937");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz99311");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-sec-atk-dos-zw5RCUYp");
  script_xref(name:"IAVA", value:"2022-A-0462");

  script_name(english:"Cisco Identity Services Engine Software Resource Exhaustion (cisco-sa-ise-sec-atk-dos-zw5RCUYp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine Software is affected by a resource exhaustion
vulnerability due to insufficient management of system resources. An unauthenticated, remote attacker can exploit this
to delay RADIUS authentications.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-sec-atk-dos-zw5RCUYp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f92365b2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz99311");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz99311");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20937");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(410);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');
include('cisco_ise_func.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

# Not checking for GUI workaround
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var vuln_ranges = [
  {'min_ver':'0.0', 'fix_ver':'2.7.0.356', required_patch:'8'},
  {'min_ver':'3.0', 'fix_ver':'3.0.0.458', required_patch:'6'},
  {'min_ver':'3.1', 'fix_ver':'3.1.0.518', required_patch:'4'}
];


var required_patch = get_required_patch(vuln_ranges:vuln_ranges, version:product_info['version']);

if (empty_or_null(required_patch))
  audit(AUDIT_HOST_NOT, 'affected');

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvz99311',
  'disable_caveat', TRUE,
  'fix'           , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);

