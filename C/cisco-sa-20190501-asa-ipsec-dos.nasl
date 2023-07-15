#TRUSTED 2ffb8289d9e45a5a7b099a8016bc2a582bb84eb79507cffd653d350833ddea883912f1c66f3273215db85dd5641fe6bb0c4e35d1d82a511bbbcb6bfefeb1c2c860c4960f5fd290cfaf47c2d0ccb29e771c0addee18fac27c4ee2b97fbe44885e7f04c72cbf8ee8d93f5374d128df6865afa99c4c4531b2494b659b9ad170c1019b94edfd09fd633cdf42ff6683943ca6ca0eb3b7b832efebf5108cc570e1208705b2eb7307d90f2ca525ee36986380cb4ee0fa5945e890012a229430085bf91f30ba4e5b5f5d7287e192227189ce4735c3bf2faf6a3cc138c26315aba3f8b489cf22501573896c7950850c7eb09e01176aafae28d6bf7c995a504e7764437699119a539348fee21c9da55839b004bdde9c2d077af52bd9b4f1e9bfa004da753452845d1b6ab3e01b637a397fbef0a18bfb52ab68b1dec93c25270ccec7a0a2bb38dfca4616939c88c8ba27c6188c9505dc47a79c5368d4d685bc44e0826eef7b2c4bf66842ba103b5e3367af3990a1c2d80907a825972d46e17fc7910364eeafa57f3d7107c9681cfc800183ae3c02c977d587792706d38266b054a785323fbc6fc10d334ba274d0d5b65954d1121ec34aaf3d71b3641ad380d228ec35385d76961711354912b612692d5085c63c09ba108e7f109e25545d61e519275440a0b9fc755d1473905bc9860fa04c0817b1fc28101dbcd2e06564d49986db32e07612
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136829);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/23");

  script_cve_id("CVE-2019-1706");
  script_bugtraq_id(108144);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk66732");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190501-asa-ipsec-dos");

  script_name(english:"Cisco Adaptive Security Appliance (AS IPsec Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco Adaptive Security Appliance (ASA) Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Adaptive Security
Appliance (ASA) Software is affected by the following vulnerability :

  - A vulnerability in the software cryptography module of
    the Cisco Adaptive Security Virtual Appliance (ASAv) and
    Firepower 2100 Series running Cisco Adaptive Security
    Appliance (ASA) Software could allow an unauthenticated,
    remote attacker to cause an unexpected reload of the
    device that results in a denial of service (DoS)
    condition.The vulnerability is due to a logic error with
    how the software cryptography module handles IPsec
    sessions.  An attacker could exploit this vulnerability
    by creating and sending traffic in a high number of
    IPsec sessions through the targeted device. A successful
    exploit could cause the device to reload and result in a
    DoS condition. (CVE-2019-1706)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190501-asa-ipsec-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?195b41d9");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk66732");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvk66732");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1706");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(404);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/model");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

if (
  product_info.model !~ '^21[0-9][0-9]($|[^0-9])' && # Firepower 2100 ASA
  product_info.model != 'v' # ASA
) audit(AUDIT_HOST_NOT, 'an affected Cisco ASA product');

vuln_ranges = [
  {'min_ver' : '9.9',  'fix_ver' : '9.9(2.50)'}
];

workarounds = make_list(CISCO_WORKAROUNDS['crypto_map']);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , make_list('CSCvk66732')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
