#TRUSTED 13953874d36d271165035e4e7671a0c56576dfec4416348258b0ae8cab912654829d179f5ffb2832b64b24f58e19e526376d8b5d605cc85e52fa31191c2c36d1eb0f64587c6def9346c802683a795c49c07993d4cba9fe8f1f2c911e13b6a4aa29bca6b0250811d420053073423f804f718f7c8bacc7870e6d2736c5aa0de466253fc5cd98a5c2a46f64d04a38631fe8bb8f3ab1bd5c5aec5e9098dd5fa64bc228251b5582a543cd43725eda7437e4e1ec495b998a5273f09537803458c90606dc686b341faf623f259dfaeb354cc0a9fa2e45496220f0e7ccd1b1dda0eab3505fb302d30b9beaf6ea3e9d8069da683f24f0513680018f3be46ae49508d52ba5cd6cce6d6b6f7af1af7e6d84a4aa33ba3f96bae109903656c89887c7d9bd357c9bd2e4bebddc453a82a5b274a572d9270b8c2abe175b5b9e2398c16accc314847b7c3442c2a33e5eaa34e28325bc42052c88f2e87c5af7629e5e32483ff60d253424c7c20fcc269a81635d6dac4f749d80bde3aff520fadcdd5ecdc4ecc6a9575352c36626dab66ffd90563cc4ae218214ca172fba3912bfdc15eeec15cbfbaf7b25322a9893ebe7ba83344dffbc29d02737fb865d48585f2963fc4681196bd4673fc744628ecd7350444cd7ffa9bd206ae9069319a4e6ca9da48df6985ef159c8f5d1c5441c5d32cbfd4f08ad61556b6ccbf101fd28e43044506bc83f44d009
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145422);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/27");

  script_cve_id("CVE-2020-26073");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv21754");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vman-traversal-hQh24tmk");
  script_xref(name:"IAVA", value:"2020-A-0509");

  script_name(english:"Cisco SD-WAN vManage Software Directory Traversal (cisco-sa-vman-traversal-hQh24tmk)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage is affected by a directory traversal vulnerability due to
improper validation of directory traversal character sequences within requests to APIs. An unauthenticated, remote
attacker can exploit this, by sending malicious requests to an API within the affected application, to conduct directory
traversal attacks and gain access to sensitive information.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vman-traversal-hQh24tmk
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f2bbccbb");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv21754");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv21754.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26073");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(35);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if ('vmanage' >!< tolower(product_info['model']))
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver':'0', 'fix_ver':'20.1.2' },
  { 'min_ver':'20.3', 'fix_ver':'20.3.2' }
];

#20.1.12 is not directly referenced in the advisory, but it is between 20.1.1 and 20.1.2
version_list=make_list(
  '20.1.12'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv21754',
  'fix'      , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  vuln_ranges:vuln_ranges
);