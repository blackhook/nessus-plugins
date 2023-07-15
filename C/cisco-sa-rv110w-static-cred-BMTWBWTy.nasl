#TRUSTED 86c6e54245ca5e25b1c651b1af6c9d676bc527556181d06e4d6540de35f2da8689cce54bf6aeefb966a9b0662411b4fa454eed4d906a34184d86f33aa0b76a32d68b432a047174315ce67bb42f822b02fc929530139512022b9d85c6243b14e430cd78754e518ab05290788e3cf0089b1016c6313aeae99aba213777e62fdef8547148c1b89a499c42061bdd698f38ffe11059e30b77e37398b113d20cace10294f69fe9780a4caca0d92353382a7a3109d22062a9c7a820f9e3bdd2d6f0bef03753085430a7ecde76127c1a154ad97a724ad76772a78ff8f31e53612584acfddb7936518738d0df99b834dc07c172eded0e9db6e64085cc9862a54996ac1509f88b0a40f53c831db5d802eb2e4a7063276f90b34de8117c4727d3b7b0f52f92a13bfa9840e4ed578dd40b6bf84d91edd03525ae879b35c7cfd2ef1cbef8301920c708bee3d5d812aa74685cb22b3454bf1d45587216f6983bb61fab80536ffdb9af17463ec6528821fe5a3b80f3d40b2523ccae4243a864dac55bb8fd4b15ccb3e15b412a525e375c20d551f51f982fb1a315ef2bc1a74050886259c3484783870ddaf6673ab3a209f41de08b9990740df8dfd1bd0643115243f576089465ac4a6b452d9e5dcb0ddebc151769319e2fff5b208e18777d62cc6845d361cf5cf6ee796a558ba757a82171314592220be57270f4f35ac39cc9c4e5460ef2616b8e
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139747);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3330");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs50818");
  script_xref(name:"CISCO-SA", value:"cisco-sa-rv110w-static-cred-BMTWBWTy");
  script_xref(name:"IAVA", value:"2020-A-0331");

  script_name(english:"Cisco Small Business RV110W Wireless-N VPN Firewall Static Default Credential (cisco-sa-rv110w-static-cred-BMTWBWTy)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware is affected by default
static credential vulnerability. Due to a vulnerability in the Telnet service of Cisco Small Business RV110W Wireless-N
VPN Firewall Routers could allow an unauthenticated, remote attacker to take full control of the device with a
high-privileged account.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv110w-static-cred-BMTWBWTy
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?11ecf258");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs50818");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs50818");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3330");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(798);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:small_business_router");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');
vuln_ranges = [ {'min_ver':'0.0', 'fix_ver':'1.2.2.8'} ];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs50818',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  models:make_list('RV110W')
);
