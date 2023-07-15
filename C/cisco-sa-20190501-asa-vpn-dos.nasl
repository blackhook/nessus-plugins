#TRUSTED 1be040b15a58d5c8514c08a278e2c60169a336f47a087bd1134120b728f5cc3721d7d3335185d48e65710c1737271853f5d602009e528da7065dd18e63fa7a178734102b91e04be7dd6cfdee517238b2cf2c46486863d0d5026459c9a81a730d4d3ced9b4fbea2baccda811aa3efab4eecf0e4548c4a34ac98538e0b38b542a6571d2238b951146754f09bd8ec3582f84aebbea5af136972b2d2eff484ae2f1ebadfd40321f31de12d4ce0a7fe04aee17e6c34e6e75343e3e25b45a52c03b738cbc3193e4f00c0942d087638526526180f7a6b63e99bddb346b498f90c4a2c08a4a46bde6f6afbfd5e86cd01c31792046f77a4bfffb1ed9e8bab5627a1b922eb868cb06d42fdbf1f812e0e57ddaa99cfb60dc9b254616fa268c00adf0c3619d651393784f3f582dbc6693e24a3fdfc31d9b0939f04ccfa99a1f030502278848b333013653ecb8678e5030632622b6b8f72c3c1846340838ebfc76ab6370657fe034a721dfd424a9161c14ea669ae97ab150ee3800250016106f307975554fa96fde1ef4f119119201d875c44bb23d471f598e2054e94c53416fe91308fc343d019bbe8d4b26a04ecd99e6c5a6faad4cdf5ec18a085564f7ca3b3f2069e6443dd5a235794845e6d1a89e0de614ccb570ce6174c89b76f17a3a6e2fce83e12871936a47e92d4ed4926b75f8e9befe3c98c1ed315e188baae8ecce1e12e23d02059
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138380);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/14");

  script_cve_id("CVE-2019-1705");
  script_bugtraq_id(108151);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk13637");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190501-asa-vpn-dos");

  script_name(english:"Cisco Adaptive Security Appliance Software VPN Denial of Service (cisco-sa-20190501-asa-vpn-dos)");
  script_summary(english:"Checks the version of Cisco Adaptive Security Appliance (ASA) Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Adaptive Security
Appliance (ASA) Software is affected by following vulnerability

  - A vulnerability in the remote access VPN session manager
    of Cisco Adaptive Security Appliance (ASA) Software
    could allow a unauthenticated, remote attacker to cause
    a denial of service (DoS) condition on the remote access
    VPN services.The vulnerability is due to an issue with
    the remote access VPN session manager. An attacker could
    exploit this vulnerability by requesting an excessive
    number of remote access VPN sessions. An exploit could
    allow the attacker to cause a DoS condition.
    (CVE-2019-1705)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190501-asa-vpn-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?706ff5cc");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk13637");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvk13637");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1705");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(404);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

if (
  product_info.model !~ '^30[0-9][0-9]($|[^0-9])' && # 3000 ISA
  product_info.model !~ '^55[0-9][0-9]-X' && # 5500-X
  product_info.model !~ '^(21|41|65|76|93)[0-9]{2}($|[^0-9])' # 6500, 7600, Firepower 2100/4100/9300 SSA
) audit(AUDIT_HOST_NOT, 'an affected Cisco ASA product');

vuln_ranges = [
  {'min_ver' : '9.4',  'fix_ver' : '9.4(4.34)'},
  {'min_ver' : '9.5',  'fix_ver' : '9.6(4.25)'},
  {'min_ver' : '9.7',  'fix_ver' : '9.8(4)'},
  {'min_ver' : '9.9',  'fix_ver' : '9.9(2.50)'},
  {'min_ver' : '9.10', 'fix_ver' : '9.10(1.17)'}
];

workarounds = make_list(CISCO_WORKAROUNDS['show_context_count_multi_context'], CISCO_WORKAROUNDS['tunnel_group_remote_access']);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvk13637'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  require_all_workarounds:TRUE,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
