#TRUSTED 948ccf939fb893959d7d38eb80f7b5515b7bf0dc5b4f31758b2a22fb0761b1d23b51f0c28ec26bfd2d93746c5cdcaa21a81decb82543aee7bd728755524cbe040dbdbf60d3bc189adc38b62871b5678004a2bdf55979fce6d8aa016fa76ff9ae116928681815a59411109539dd98dcc4b95608cca43b13cada4452e78d6862657c0861b8fa40229ccd87d233dbbae9514b604d0c27b405a1422522be0fe3205f139c8c6cc6a949a0f9807b10f7dca8bcc3350decfaf4fbc4631dbb006c640061433645418b0974c5542def8a441691fde2ed93a83db8b7a94fd32bb6a1e595aa76aed5b64ca18bbe84fd28b8530a151c9154198a9a7a71d2976f4f90938382cdded3a182eb96b3269f91187ca4008707d1b5a8d0f5f9b0fc78c56038ef1583a8c4764da4bd5a3fe50f4a4c1bb1a2ee53ea2e38ae8083c4c29575195406e569c8090e56b96a3a3e1cbeea6b5b800d6a83212e62204b2691304e304030eb0ed34050f46a127210595ac93c2666551629a42c4ee802aae6ce5840d14e9aa27d6860be24eb45a79804a4baddf2ce91d3efcd085bb31bf47d9f1692eb5a279b60978bde8b5f7878b2a5adef2c7213eb1ab28b787bb42d9f9b944941b8e9a7db3ad88cd8aef06f0b79b339f632f95f72f930723dc52784991b9b16664103fde24a9f00069d8019414f4e999052c53fc94402f7f2abfa39ee6dc68fef2cf34356397b2f
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(148968);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2021-1362");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu56491");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cucm-rce-pqVYwyb");
  script_xref(name:"IAVA", value:"2021-A-0162");

  script_name(english:"Cisco Unified Communications Manager RCE (cisco-sa-cucm-rce-pqVYwyb)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Unified Communications Manager installed on the remote host is affected by a remote code execution
vulnerability due to improper sanitization of user-supplied input. An authenticated, remote attacker can exploit this,
by sending a SOAP API request with crafted parameters, in order to execute arbitrary code with root privileges on the
underlying operating system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-rce-pqVYwyb
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c59ecd3a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu56491");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu56491.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1362");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Unified Communications Manager');

# 11.5(1)SU9 - https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/rel_notes/11_5_1/SU9/cucm_b_release-notes-cucmimp-1151su9/cucm_m_about-this-release.html
# 12.5(1)SU4 - https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/rel_notes/12_5_1/SU4/cucm_b_release-notes-for-cucm-imp-1251su4/cucm_m_about-this-release.html

var vuln_ranges = [
  { 'min_ver' : '10.5.2',  'fix_ver' : '10.5.2.9999999' },
  { 'min_ver' : '11.0.1',  'fix_ver' : '11.0.1.9999999' },
  { 'min_ver' : '11.5.1',  'fix_ver' : '11.5.1.21900.40' },
  { 'min_ver' : '12.0.1',  'fix_ver' : '12.0.1.9999999' },
  { 'min_ver' : '12.5.1',  'fix_ver' : '12.5.1.14900.63' }
];

var reporting = make_array(
  'port', 0,
  'severity', SECURITY_HOLE,
  'version', product_info['display_version'],
  'bug_id', 'CSCvu56491',
  'disable_caveat', TRUE,
  'fix', 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);

