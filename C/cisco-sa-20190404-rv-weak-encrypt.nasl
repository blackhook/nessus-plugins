#TRUSTED 776a2e5cf6cb6537063883f3d6ba4abd45952c0e679ef88bcdd976aa81fb46237b84daf139874717701e00718357bb26a0639f50932a20c8d97e3005976a0ee1405058dad34b74c49ed78d73211c9c2c18c867ecd08b2fc624d8ba75bc5176bbecd97c309102576bd088a54df98d84fe1f6e0b88d2db613effade5b8c238bcd7167edeb297f9bbf95fed5b0d6e8f656a19c491281c7b0545bee0fcd3c04621c41d64bfa4994b600ee28173722db7a348a045776dde653b3112ab0769837d89e94d58671b63538e7503603ee2cebb6615b7c03618d1c6eafa8c3c1e5c148d5f8b2f7fdaa68c42705ca6f24c8b151316e9d1b58602e4164ef66a261b52c23d37fb928a9bc3c801e8a24241baec6ee121399e4346ab24de9927fa13fb27f1068f62ba0d88c5c7105156d8f6480eb118972953b3d77c98dd6aa471d2cfb3c10d738ff0b0bc6ca736013fcf5f8718317a9a9b0f5dc90fc01ae71becbc3209aef3f961d1d89368ddd5a7d1d3162032be15e7caaf6351636dd4f461a6b2212a697b9761bd8a074672a01f697d8408a4cdb41acd3b99c64ca82f96c46028157b5e2930d3054f3062eafa1b669933706d6854d4b13a607bb4293d46dfbbad222c372c4797e77d4b1c0df18d1ebeeea906d6232892ae78f0d33071c50e96e0933aeb60934c2bc63d3bc38f9912f0bd8629588afbfd9d8414d35b3f452000f31596caaedf84
#TRUST-RSA-SHA256 98a64a495b368b68ffc24c7939a53aa3810495a4b940d14156bcaf1957fac6fc6be9dc3845e0eb7c099ecfc2d16c95341115e56dc65cfa6d9e0e9c101883679e979418108921481c2b12555215cb5a826d8d14244791181443ba08d334032206f9252687898aab6af30501f51f876898bb1cceef6c15208fa6425c8b3e12657e20db8974e212aec50149d581eb017559374513e10d179b3e949dc828c09db1ab317f01efbc959af867bdf7b28b588afac38ecf9869be6996cd2037131f8d99aa2008a0a3bd3b4cd50f6c4f7c79bae323c96db003bc6828b0c91a9bcac45701487b8e67bb496ded2f41f5a571db336ff073e179ea5813c723fafa4b4e8fdac7430c3a11bb12b880ed5e528027d2e08508bc4257fc1ee322c9cd4e1a17eadb089c110599bcad23faee6bc5e52f7d98828d6cfb3a6598945a54ed4dbe377bffdd2f80608e9d94e2fb2eed0b1946874c894eec0f608bf20f3723673483493af7adbe263b8372af78938289118d693fc555ba7100cedc9641ecf039456f8e564afb2687432a9aa4f5c8b649e86755ee630098b9a64f477ff458e4bcfe74acc6eeffa272727177f9b5e6d38dfa8915036f4b099c8a4fca0a721e00cf356ac0b5f0efaf7749294efaea6b2690044d152f115e332315ea1aa00570b0dde725aeeb900b53c3b5bc30e37b56a7ffdf10f7b8e28beabddf4ed830f3eb0f303727744f2c42ef
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(124061);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-1827", "CVE-2019-1828");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp09589");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp09573");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190404-rv-xss");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190404-rv-weak-encrypt");
  script_xref(name:"CEA-ID", value:"CEA-2019-0212");

  script_name(english:"Cisco Small Business RV320 and RV325 Routers Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, this Cisco Small Business RV
Series router is affected by multiple vulnerabilities:

  - A vulnerability in the Online Help web service of Cisco
    Small Business RV320 and RV325 Dual Gigabit WAN VPN
    Routers could allow an unauthenticated, remote attacker
    to conduct a reflected cross-site scripting (XSS) attack
    against a user of the service.The vulnerability exists
    because the Online Help web service of an affected
    device insufficiently validates user-supplied input. An
    attacker could exploit this vulnerability by persuading
    a user of the service to click a malicious link. A
    successful exploit could allow the attacker to execute
    arbitrary script code in the context of the affected
    service or access sensitive browser-based information.
    (CVE-2019-1827)

  - A vulnerability in the web-based management interface of
    Cisco Small Business RV320 and RV325 Dual Gigabit WAN
    VPN Routers could allow an unauthenticated, remote
    attacker to access administrative credentials.The
    vulnerability exists because affected devices use weak
    encryption algorithms for user credentials. An attacker
    could exploit this vulnerability by conducting a man-in-
    the-middle attack and decrypting intercepted
    credentials. A successful exploit could allow the
    attacker to gain access to an affected device with
    administrator privileges. (CVE-2019-1828)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190404-rv-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7ea0bf3d");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190404-rv-weak-encrypt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75b1813b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp09589");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp09573");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvp09589 & CSCvp09573");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1828");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79, 327);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

vuln_list = [
  {'min_ver' : '0', 'fix_ver' : '1.4.2.22'}
];

reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'fix'           , '1.4.2.22',
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvp09589 & CSCvp09573',
  'disable_caveat', TRUE,
  'xss'           , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_list,
  models:make_list('RV320', 'RV325')
);
