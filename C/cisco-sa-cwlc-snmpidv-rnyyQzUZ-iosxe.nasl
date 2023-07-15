#TRUSTED 52e0b68705b26297a5817baa78c967324ef9450b2bc12e5af562857041143824ec8fb6cfe4e2dd7281cf5db1f3774639d01194dc688e911440a448698170485d74aac5babbda0851d9b4dd569f2af09f3180a3f429d02217343de0f92ea39e86252eec084d0027de6d83a36bf88202cd85be36f064792888306f8be0cb9e91c544ca4c3e3914b78c64d8d60637512529cf8d9f6349145e42a3784d9d2ab104e9ec34a755f01faade8029a05b2cf09189381aaedf9dacb1bb80dff7822ce5d5dda63921d8ba75398bd00a1d75e7c78095cf390828cecc5b7d4459ff066720bcf6d658525b1c52789a8cf83387007cebfd5da75ac4746f2f1c3a4ee3d5abae2d01bbef8a16f5ada72da942cec1d5adbf13301e9bf10959d43150dbb4052faa8e3677a950cfb43b33aab1fe83c86e770006d859378d12efb8fb1e0724f944cc96a886cd66c9ff7a2960e6ff239bf0f2ba7ec7645018602d1ac6a33e66cba280552fa0637f686bca658942e3df08a3537b01ab7c8fe268e239f814d7dfbb2291247afb5c89e07807b4f888e858b8ac8f9952142f9d501a6423c9ce60f3faccb104835e4ac829b110988b6f6358f375cb6035b3306e4a0206bf282be1f0a8512a462f7146ad66b5918b6dc1c4eabc578dc6019012a684858707061fcb835ac02170e1fe22a67a8932f0a28aa537496c62a21b80d1385fce10dd2c3ae6bc362748b4bb
#TRUST-RSA-SHA256 b042b4e9ebd3ca2c9ed434ec6de9790f166215fb278c5ddba0b9a10a21a3633d360ecb02eb420009225c85d58a545e275ad552de7aa1c9b87fa973e192552873ffe9934756de64d043613604739df51613be3ec2ebf14ed29e30c3955453d897b666a15d71f73c97a642ab0a7b19a1ad2d42007dfedb020ee9fe9d45b6a926da48353c8ac2949518bca5dfa95b53fc55ad430ecdf892792971715fca43a809099130c132d12c848458212ce6da7e218d75042639f611e77af1136e341bc7dd843d43963facc3b604e9fe7720a1092b4d2ea186c76acf25332f75d6df287414d0a8ee9e7e7e88dcbd73a49b7e03b21f20aab83e3ea641baec2b51a5c6f138b5ef1d8b090253a51b66de3fe2329a0964ba1612aa97673c72b910b8c74c679b394f71b652f6c7bb68ae29eb0f8c30a4eef75daf6915308fb3175faa9bf90a0ff93fe34fd693fe952f0d346e42eba50bfd9bb1822e817fbd18866d95844af4ab74e5cfe09793cb6f34f5e0094273fece78abb9b471371c157286c08a9b92aa711f2e37e84e39f52d389a81d38e12e088cb8ee2b5b1852e93f8df6100241dcf00f8c75f960eb9efbd7a9cd9cc43b9e5304de7af59bb023d315c52b9b471aca876c32942029c9246d75989a529f5372c4ad4c23b0f2704708ae6bcfedf20188a54f38391f6643180e43aad5320ee6b4e0ced5122d37dc0c2dffa2ef72725dace50ef65
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166017);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/29");

  script_cve_id("CVE-2022-20810");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz99497");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cwlc-snmpidv-rnyyQzUZ");
  script_xref(name:"IAVA", value:"2022-A-0390");

  script_name(english:"Cisco IOS XE Software Wireless Controller for the Catalyst 9000 Family SNMP Information Disclosure (cisco-sa-cwlc-snmpidv-rnyyQzUZ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by an information disclosure vulnerability.
Due to insufficient restrictions in the implementation of the simple network management protocol, a remote,
authenticated attacker could retrieve service set identifier (SSID) preshared keys (PSKs) that are configured on the
affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cwlc-snmpidv-rnyyQzUZ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?03f08c7f");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74745");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz99497");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz99497");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20810");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(202);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  '16.10.1',
  '16.10.1e',
  '16.10.1s',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.2',
  '16.12.1',
  '16.12.1s',
  '16.12.1t',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '16.12.5',
  '16.12.6',
  '16.12.6a',
  '16.12.7',
  '17.1.1',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.2.1a',
  '17.3.1',
  '17.3.2',
  '17.3.2a',
  '17.3.3',
  '17.3.4',
  '17.3.4c',
  '17.4.1',
  '17.5.1',
  '17.6.1',
  '17.6.2',
  '17.7.1',
  '17.8.1'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['snmp_iosxe'],
  WORKAROUND_CONFIG['psk_encrypted'],
  {'require_all_generic_workarounds': TRUE}
];
var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCvz99497'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
