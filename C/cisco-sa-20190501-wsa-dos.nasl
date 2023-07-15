#TRUSTED 1e764b9658e232dae035846f06d67ced50def27c295ec51789fb15055cb923f0cb4eb96868060778028855b3e284b51ebd7eb05fe3c021f500f3ef3d4de17e1d8f9300726a31cfab8482e8d191d980183196053504d70e32fbbab13070c45c02ead6454b3ac5dd55d651362292224af0abd06e0249ed0d9c11c10e792795c2e089d961745bcbe4b1c2bf403bef2299de37c845a4ac3e3299e65c39f61e0d6c185df25078a35bad0a0f178bf31a2e282f91ae2a0716f6ff2a615b93aac6667289548252aa71eb413b5495c60e0d43c9b739736717183fdf8fc03738d2bf48115f035285711d7ca85e9a2c72ca6c3d9609e899b8cf580eeb7c04b7a7a29b215c54e196973cb612a0192b3e822476bce54078a58492ad0069722c1e6c62f365864d4e4daad05d0ecd9720dd2846ea7e28e43ab24f14038371eb77a1e5630bcd878778990e1b81c3205a134efddd5eddbe9cfa7b85569e010b37a10a25a57184d9dc21cf57b89178816885b1e790c0f352bf5d4542d65c892748649c4d9c1ebeaa4fd71c18c273f2bc1586bd5ab13d6c1a18a76717dfaa808c03bc4eb1578e657c7a3c8940d44b7a2cd87f3bcc7a7de8163ec5bbe98d2585126f150436af7f50e2ee29d65c94823afa73b2b53ab17dde14547991f34f89b94d8dea0108a9c61402470957733d7f6aa0c0c5345096656ca639fd309f2a07b093e494b5734958697f7e
#
# (C) Tenable Network Security, Inc.
#
include('compat.inc');

if (description)
{
  script_id(126632);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/14");

  script_cve_id("CVE-2019-1817");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn31450");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190501-wsa-dos");

  script_name(english:"Cisco Web Security Appliance Malformed Request Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco Web Security Appliance (WSA)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Web Security Appliance (WSA) is affected by a denial of service (DoS) 
vulnerability due to improper validation of HTTP / HTTPS requests. An unauthenticated, remote attacker can exploit this 
issue, by sending malformed requests, to cause the application to temporarily stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190501-wsa-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ed846d6a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn31450");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvn31450");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1817");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/12");

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

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Web Security Appliance (WSA)');
workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvn31450'
);

vuln_ranges = [
  { 'min_ver' : '11.5', 'fix_ver' : '11.5.2.020' },
  { 'min_ver' : '11.7', 'fix_ver' : '11.7.0.406' }
];

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_ranges:vuln_ranges
);
