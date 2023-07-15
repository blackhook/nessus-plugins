#TRUSTED 23178aac7729500e2a3fd0c7dcb47c926f924afe1c7ad7ff06bd66af519824e734d8621cd3cf42bf9debb95204352b31b053157b09c1c9ced336ad018397041a0f3f50b1be2b39dee8d80c66e53f190db21490872b3081f7349a73ffa8c38ddd29fa1674ea9a7d697a97b1a03101849d355d4b63aa1d74caea032ae93026446f4532e0b73df662fa870c0bcb0067005e00bc6fb54197350e7b316799412beb11a5c941027e947b7624b667be9faab3c78c053c774fc31a7e400f45a2373e46e05754fb4f24ce3bf6a3f9cb1be92d936317d378cf4c64d1b0db4a87b2f96777bda1d9ac5d936752f56aeb12f9c0c24f03b102c95c219b1245a05a6502fc47f62057f0f61da5589f100bb5982841a8b8700b2e7ed35a842bd58352fd7fa2fb1f68e2db2ac5c023c4e56782b4b7ef28cd2cb341c1e91d1ccd95e941168937079076da86e6977fdbe1ca0cafe4600bbd1aa773fc612179918144daab04ab7f8c750953ffa4a4f61c0c01736cb6ab3ca25462dd69ec9f857359660433f86a914007c75a03ef9aacc81ba1c1602c1809e9358add3f055466c078637e7e1a50653e2ef53d669457d34608ddf5aadab8b411bbdfac0600fdb6dfb3e9bb1a2b17d3a54b67a5f40fbe2e8b44781cce8d91bed48efcaf2d34e6eb1181d70d84e1a98603dc7f45aa424689b7931482d8d46019d80f225412d0a89617ed8290d6ccbab72fe465
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142365);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/07");

  script_cve_id("CVE-2020-3387");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt70892");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmanrce-4jtWT28P");

  script_name(english:"Cisco SD-WAN vManage Software RCE (cisco-sa-vmanrce-4jtWT28P)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage is affected by a remote code execution vulnerability in 
its user authentication processing component due to insufficient user input sanitization. An authenticated, remote 
attacker can exploit this to bypass authentication and execute arbitrary commands with root privileges. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmanrce-4jtWT28P
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6efd7427");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt70892");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt70892");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3387");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_vmanage");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if ('vmanage' >!< tolower(product_info['model']))
  audit(AUDIT_HOST_NOT, 'an affected model');

# SSO check requires UI
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

vuln_ranges = [
  {'min_ver':'0.0', 'fix_ver':'19.2.3'},
  {'min_ver':'19.3', 'fix_ver':'20.1.1.1'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt70892',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
