#TRUSTED 03178ae7353b33e7a0bb41f6afd61d6ba5f2ad367b152a41a64fe1670c08ca7e7625ce4edf2ac4d2133cce0325372e70615f95cdfa59e1bf4805f0d407b0e7b177546bfcbed3918753d5f9ab141be412398dbf3e26f120e32d14c92b4f15ca6d78144899850138bb1878fbf1ce43a02d9c8c1bd3cfeee04d0d8956a4e8e5f064365ec2b4974eb401830b415b66522c938af38a7d279f268c6715a1cf5bd409a58b6dc11b0a6493f0308308373dfa29837d9c6605db793be611e5393e45a59173731bc69a4144b795eb54f0be6dc783ed2067258cd5dc9e44e02d07ac1a163d0c5b8b75be7eea6efd1573820c3e8ee461a587c80c6c81199066a982791539f6f500a98822cda20884c4c10c736fc8a9193e791812a0bb6790f79e13438a87616098c65aff3487f2b127b38f576b6a51940a0388475a1fdf0a514757a26298b85f29cbfe11ff03bbb8432aa4d299f87ecaa27913ad54207e7ba9afc0aa526f93ec5e44042bbc9a23663b53d4694611f369888ae1efc23eefb0a696ada028e32521f632b5f83f3a93f89daa33dc8ca11cad20bb6f1015ca1159334f195fadf7c2f64386bb316c3f66a06e0ea1e9308159c0020bfafc46903a10549a023793e696782673e83cdc06a358734dd967eb7197684159d36f8b0e295b8434745fd3ad9e14caefed698061d52e18af771a8bde9038d2209435ce847ebe95a73fd8d0c64ff4
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145551);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/02");

  script_cve_id("CVE-2020-26065");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv03658");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmanpt2-FqLuefsS");
  script_xref(name:"IAVA", value:"2020-A-0509");

  script_name(english:"Cisco SD-WAN vManage Software Path Traversal (cisco-sa-vmanpt2-FqLuefsS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage is affected by a path traversal vulnerability due to
insufficient validation of HTTP requests. An authenticated, remote attacker can exploit this, by sending a crafted HTTP
request that contains directory traversal character sequences, to conduct path traversal attacks and obtain read access
to sensitive files on the affected system.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmanpt2-FqLuefsS
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3d2f53d8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv03658");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv03658");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26065");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
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
  { 'min_ver':'0', 'fix_ver':'20.1.2' }
];

#20.1.12 is between 20.1.1 and 20.1.2
version_list=make_list(
  '20.1.12'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv03658',
  'fix'      , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  vuln_ranges:vuln_ranges
);
