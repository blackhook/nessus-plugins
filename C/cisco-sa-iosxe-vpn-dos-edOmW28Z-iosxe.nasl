#TRUSTED ae55b53f94c9013309d872a101761f738de9e7ff226d0d56d013af2c3479078f0c21de8fa9f64a577ae688a2279e4f51a9c07683a507fdcf5e1a73a097abbc179d89e97b6f48a6199247c1dcf063d5412f198b66ee1faf765df6e1260cf7794a10c283a118e68e65ca36bb47d5ebc3c810acaa511c0322af638fa2ad30cff55b87f99bc83e6b4447b52da9d883c4603ed37e8ba28b626b8a6aeda13a4655a43e35af2a7ace0bffb9c5aeaa940a0800ec3c9555863b27c6da3b5eb500f526922fccf414272051df1f9cf428d49a71b93997667599335a1723830087c1f22bd4ef94bdf8f7829514cb13dbc143241dbfe3138822e7686f7d81cbd84a9bdb3b1e7f32666267b63072816df790bcbdd5e120e8d1b56983810be1638281b86215ce1624778ef80d8a8cd486de72e76c63c8ae742e61f9c94290d1bdb157c94089d90f5390b2e3c9fe864b1758f26b9a411a021f92624d984fddab6e360d9786214b7d2629fe41d05455a9e87cdda4f2e2d7afdadd9dbdab72f2a52acb14e61b1674dbcf7cdd6b58a0342d881dadfa6c888482dbaf35e891aa0444ad1175026a32ae72fafaef5a66207e24dad019b57d36f58ead1d5aa757034b2bd45bb89c66801a1d1a95244bdec45026351792379235486f4271e7597edaeab3baf71eab59a142db8f38a8783ea2e81414ca8cd933cfe2f557295970385bff3ab4e06ada1bc982ed
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138211);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-3220");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq67658");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-vpn-dos-edOmW28Z");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software IPsec VPN DoS (cisco-sa-iosxe-vpn-dos-edOmW28Z)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability
in the hardware crypto driver due to insufficient verification of authenticity of received Encapsulating Security
Payload (ESP) packets. An attacker could exploit this vulnerability by tampering with ESP cleartext values as a
man-in-the-middle in order disconnect legitimate IPsec VPN sessions to an affected device.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-vpn-dos-edOmW28Z
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec976823");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq67658");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq67658");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3220");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(345);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/device_model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = product_info['model'];
device_model = get_kb_item_or_exit('Host/Cisco/device_model');

# Affects 4300 Series and Cisco Catalyst 9800-L
if ((model !~ '43[0-9][0-9]([^0-9]|$)') &&
  ('cat' >!< device_model || model !~ '98[0-9][0-9]([^0-9]|$)' || 'L' >!< model))
  audit(AUDIT_HOST_NOT, 'affected');

vuln_versions = make_list(
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.5',
  '16.6.4s',
  '16.6.4a',
  '16.6.5a',
  '16.6.6',
  '16.6.5b',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1s',
  '16.8.1c',
  '16.8.1d',
  '16.8.2',
  '16.8.1e',
  '16.8.3',
  '16.9.1',
  '16.9.2',
  '16.9.1a',
  '16.9.1b',
  '16.9.1s',
  '16.9.1c',
  '16.9.1d',
  '16.9.3',
  '16.9.2a',
  '16.9.2s',
  '16.9.3h',
  '16.9.3s',
  '16.9.3a',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1s',
  '16.10.1c',
  '16.10.1e',
  '16.10.1d',
  '16.10.2',
  '16.10.1f',
  '16.10.1g',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1s',
  '16.11.1c',
  '16.12.1',
  '16.12.1s',
  '16.12.1a',
  '16.12.1c',
  '16.12.1w',
  '16.12.1y',
  '16.12.1t'
);

workarounds = make_list(CISCO_WORKAROUNDS['crypto_map']);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq67658'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_versions:vuln_versions
);
