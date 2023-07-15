#TRUSTED a7e2a4b4a0c591a61f31574093e194dced6483a78360c4c685ed21b43b61352be980aae2c9a2f5aa3b74db5f78c55a1126b7f978704726df6de5c483adc523d1af6f709b9b0b0036ba0139cf0dbc9270b485adc2fce503319bfb2a83f111c92e0de4fd925dbfb19fc721f0e37e1cd3eed051108af833bbac64025295c47e7e6aabb150f44bc5e3f09ad742f5a40af256a160b1257efc2b958e43e5b45b365456da85c3a413f1c75471fd9a8da38568d45c7a4c47a2b243a99e42150b5eab23a9e6167c6cbe5b76abe2ecabf6480c3b658c2cd0d91928baab09c8328104f1dcd732818a2120cf8f671f91c0f25e40634b1c0f4e5ec9d717c5af7eb50cf1674a7d34c9c6c1e228dc5e2c7080970a1576e1e7383abb1fec9af1289c1bf159122def8808a9ffdef3751182a8ba8960cbd777cd8c0af40ee2297c5a7cd0de316ca48ef7f658ff25d7a70c6219a5c72b23e95a420bdb96da6d9e2b54cce684a4b261cc60c9ce34d750daf974fdabf93e7ebe0792c70d9cb1317e55fbb88528f012827d3ccd6a5b27386b0389a5850938e48fd087a3376d8b1333bfc2f8cd1f6135547b689cadb0406f7c2943f06d2c04b6c4f9b295ec19c59a9a3efd4d4bff67f5101842a411f69d68dd30480f54bf16dd55b33537f7661f6a8bf1a135dd7c322803c433619cec5dcf67022c2a541ec35ce2538e0c625e12e28dc6e81e49edd2e5a346
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131024);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/14");

  script_cve_id("CVE-2019-15956");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp51493");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191106-wsa-unauth-devreset");

  script_name(english:"Cisco Web Security Appliance Unauthorized Device Reset Vulnerability");
  script_summary(english:"Checks the version of Cisco Web Security Appliance (WSA)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Web Security Appliance (WSA) is affected by the following vulnerability:

  - A vulnerability in the web management interface of Cisco AsyncOS Software for Cisco Web Security Appliance
    (WSA) could allow an authenticated, remote attacker to perform an unauthorized system reset on an affected
    device. The vulnerability is due to improper authorization controls for a specific URL in the web
    management interface. An attacker could exploit this vulnerability by sending a crafted HTTP request to an
    affected device. A successful exploit could have a twofold impact: the attacker could either change the
    administrator password, gaining privileged access, or reset the network configuration details, causing a
    denial of service (DoS) condition. In both scenarios, manual intervention is required to restore normal
    operations.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191106-wsa-unauth-devreset
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c654227f");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp51493
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aa0b2c00");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp51493");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15956");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Web Security Appliance (WSA)');

vuln_ranges = [
  { 'min_ver' : '10.1', 'fix_ver' : '10.1.5.004' },
  { 'min_ver' : '10.5', 'fix_ver' : '11.5.3.016' },
  { 'min_ver' : '11.5', 'fix_ver' : '11.5.3.016' },
  { 'min_ver' : '11.7', 'fix_ver' : '11.7.1.006' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
'port'     , 0,
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvp51493'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
