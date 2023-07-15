#TRUSTED 1166026c2a4e2c140ac110e3c41bd15847b0f4b2702dd059ed3456a9670f7c68be8eefa75cdbc641bb1400820902b8ad05cbab50792a4accd0357b0ab4b5665d6cc8fdaff9465891ef3cce79e5c72d65bfb1a61147a79d884b9f2cb155e4201642eb590d0f6ecc9d0eb44a7dce582094291473e3c98a7edfa7a8b60635772f2e5615499604ec9a34dfcfa3668d83510932f254c3399aa4f6f16ab1f66360023f03dfd6a7a596327e7a5083638966a1d09ec625e2217cc222a763f4edaf365f3eaf8c2f9fc05c50cd013e8ff9f61a4b154ad6d253f5213f41c70883fbcffc335b02464788cde0a892d5da42c51f6914e7ab0db3951fd40703dc95ee37df003dce472540c6b8c038ef859e8c6c68b53d5c26d38c1f7a079200a2ca90bf4abd1e43999e7069dc1656dd2fd7a14b60d303197f6ea577d67ad2e3247f1e80be298abba20f10959f89d3468c300384d6011db4cd2f29ce75569d5ef8b5241f395c257c775d77be746fc013ec0cceca342fb65ec5a0eafb0309d766128007e15995518406fd80a27468e8182704a29b238555844306ae2ace7a321618cb07a570cf1f95cd0d8b05a79df4ce54bf886f30a22662faf243282e7c3b5078891a1e5267aa1383ebe9a71cbe70e3c241aed9fad8e61c49d4b77029085666903325d9e91af18c66cbde5d35d81c001aeca6bc90a4554109fe13aa80b1b44b2fe024b2cf734fd7
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135859);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-3177");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq58268");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt33058");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cucm-taps-path-trav-pfsFO93r");
  script_xref(name:"IAVA", value:"2020-A-0172");

  script_name(english:"Cisco Unified Communications Manager Path Traversal (cisco-sa-cucm-taps-path-trav-pfsFO93r)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unified Communications Manager is affected by a path traversal
vulnerability in the Tool for Auto-Registered Phones Support (TAPS) due to insufficient validation of user-supplied
input to the TAPS interface of the affected device. An unauthenticated, remote attacker can exploit this, by sending a
crafted request to the TAPS interface, in order to read arbitrary files in the system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-taps-path-trav-pfsFO93r
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?68b8a524");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq58268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt33058");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvq58268, CSCvt33058");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3177");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco Unified Communications Manager');

vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '10.5.2.21900.13'},
  {'min_ver' : '11.0', 'fix_ver' : '11.5.1.17900.52'},
  {'min_ver' : '12.0', 'fix_ver' : '12.5.1.12900.115'}
];

reporting = make_array(
'port'     , 0,
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvq58268, CSCvt33058',
'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
