#TRUSTED 18008e6ee34abb1145912f8fb8b55cc19f8a02c0f6e59427d4edb96a94c85732b821bfdc6758953dfa51c7b8ea8bf23183eaa1c8dc06bdb049d4bb099b7e65dba91f5c4aa01f3949adc41f9fe80a565162f82bde3376877f385e1c64f2d45822944abb3f51473a45d5ed633beadae3d4e1bc43a6c0020a2d736d268a20e7d7846bc95c74b00186b4f2676cf198c5d837532a54c408b2ed3c97814995c65b7427983bd34de0b058f096c122f0a73267e941e8b5da48264fcb130ca4b309d10ef2b366dbdbdee4704ef6e9c26e7d84454ecf5ea12da12b2707f66c023a12c2f94cbf08fc75c24ca5ab0c7385e296e583ce7b235cfdc78a1258754fbd410286286018c5527b356d6bb463aa4b986650c527db2622aaa52466412cb6903f3ccee94bfefeae4f45e2ae14f2651773fc2e8e55d058dcee66b11d2897759328491c3375165c35fc09bed85c1aaf1089df77aa8ab340246edab24213e2627729b3613ba731893020086d0c95192c7d875255e6c4ad00081b85dd178806e231b9118d67cbbefd20d587234bf974d47b689b1ffcaeed1e922e97180276fb544891eb19991b1931ab8b86ea58e2d21333087bbd517d77f9859478726b3876a4ced3b770e0f466f8ba579e9f39c42d77dd97e224e6ced7330a8fbe91f7370c894b72dcd083e31cb6640a734d4ce76810c4776284cd04afa5cec117f29b6bdf3e7fa88adec034
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(139605);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-3346");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt01170");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cucm-selfcare-drASc7sr");
  script_xref(name:"IAVA", value:"2020-A-0297-S");

  script_name(english:"Cisco Unified Communications Manager Cross-Site Scripting (cisco-sa-cucm-selfcare-drASc7sr)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unified Communications Manager is affected by a Cross-Site Scripting
vulnerability that could allow an authenticated, remote attacker to conduct a cross-site scripting (XSS) attack
against a user of the interface. The vulnerability is due to insufficient protection of user-supplied input by the
web-based management interface of the affected service. An attacker could exploit this vulnerability by persuading a
user of the interface to click a crafted link. A successful exploit could allow the attacker to execute arbitrary
script code in the context of the affected interface or access sensitive browser-based information.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-selfcare-drASc7sr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80d8846d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt01170");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt01170");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3346");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Unified Communications Manager');

# At the time of publication, this vulnerability affected all 10.5(2), 11.5(1), 12.0(1), and 12.5(1) 
# releases of Cisco Unified CM and Cisco Unified CM SME software. The Bug ID only mentions affected
# versions 12.5(1.10000.22) and 12.5(1.11900.146).

vuln_ranges = [
  { 'min_ver' : '10.5',  'fix_ver' : '11.0' },
  { 'min_ver' : '11.5',  'fix_ver' : '12.0' },
  { 'min_ver' : '12.0',  'fix_ver' : '12.5' },
  { 'min_ver' : '12.5',  'fix_ver' : '12.6' }
];

reporting = make_array(
  'port', 0,
  'severity', SECURITY_WARNING,
  'version', product_info['display_version'],
  'bug_id', 'CSCvt01170',
  'fix', 'No known fix, refer to Cisco advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);

