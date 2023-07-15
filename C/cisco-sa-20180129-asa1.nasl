#TRUSTED 21d9ecdef7286d1d32dce13167d9286f084b940478261370d0cc367746646a0ca0a76c0d589ced01b0a6d376e2696a3fb095c5144ee20429b398a5bde052f7447ce3d283d2e45384d2701604374cb5ad81fe7e436ca77aab39dadb7eec61e5ac479ed84a14abc8177f25ccac0c2594e7aa534cd03aea4a2e7109b24de79d9ebe9a1babf8e26c4150a2c326b3fe2c144089d3fa3b8b814b2384460ae5eb869d2308611937d02e453de31cb6a00fe60b7e1f054c1d34438347a489e5ff27a2bf10ffb7fcab8386272c99ddaf57ed757df8b614a5a16c0d1acb1d9d9e39b2a870004406af574f8ffa047173a58bb338a9de71bd446a0221cdbf2268a251dd1f1e15b550314c584da6f6497a54c10f66f4c912e2f4df4985c23953809289316703167c94ff8bd83484980be24d281601760d5d7b1299784c3e26e82ec3a70ee83e7796e5ca9a3d3da6a6977e457afa683fa522703100008dbd242b0074b5641b46c8d41e73fe70f88c2602c2a6c573ce6f71881dbb649bc5e357d1e2cb0380d76f4edf239e76cfcd9499358ec10767ee7b95f749d403253e60894a4b6c92146b25e55dd66a379c5d8e88cd603764024435ee456fe4d2bf784156b34001f575e848e7167abf1d6cd24e42cd331c0d7a0f3d0660fa8956f35806e449465b9728803b6b293f938e10cbfc81cbf4e81dadfaa9f22d60aa67ea8ae7d5a909f6fd9085a2ed
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106484);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/28");

  script_cve_id("CVE-2018-0101");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg35618");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh79732");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh81737");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh81870");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180129-asa1");
  script_xref(name:"IAVA", value:"0001-A-0011-S");

  script_name(english:"Cisco ASA Remote Code Execution and Denial of Service Vulnerability (cisco-sa-20180129-asa1)");
  script_summary(english:"Checks the ASA version.");


  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version the Cisco Adaptive Security
Appliance (ASA) software running on the remote device is affected by
a denial of service vulnerability which could allow an
unauthenticated, remote attacker to cause a reload of the affected
system or to remotely execute code.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180129-asa1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?118d2746");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security
advisory cisco-sa-20180129-asa1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0101");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco Adaptive Security Appliance (ASA) Software");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (
  product_info.model !~ '^1000V' && # 1000V
  product_info.model !~ '^55[0-9][0-9]($|[^0-9])' && # 5500 & 5500-X
  product_info.model !~ '^65[0-9][0-9]($|[^0-9])' && # 6500
  product_info.model !~ '^76[0-9][0-9]($|[^0-9])' && # 7600
  product_info.model !~ '^93[0-9][0-9]($|[^0-9])' && # Firepower 9300 ASA
  product_info.model !~ '^411[0-9]($|[^0-9])'     && # Firepower 4110 SA
  product_info.model !~ '^41[245][0-9]($|[^0-9])' && # Firepower 4120/4140/4150 SA
  product_info.model !~ '^21[0-9][0-9]($|[^0-9])' && # Firepower 2100 SSA
  product_info.model !~ '^30[0-9][0-9]($|[^0-9])' && # ISA 3000
  product_info.model != 'v' # ASAv
) audit(AUDIT_HOST_NOT, "an affected Cisco ASA product");

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '9.1(7.23)'},
  {'min_ver' : '9.2',  'fix_ver' : '9.2(4.27)'},
  {'min_ver' : '9.3',  'fix_ver' : '9.4(4.16)'},
  {'min_ver' : '9.5',  'fix_ver' : '9.6(4.3)'},
  {'min_ver' : '9.7',  'fix_ver' : '9.7(1.21)'},
  {'min_ver' : '9.8',  'fix_ver' : '9.8(2.20)'},
  {'min_ver' : '9.9',  'fix_ver' : '9.9(1.2)'}
];

workarounds = make_list(
  CISCO_WORKAROUNDS['ASA_HTTP_Server'],
  CISCO_WORKAROUNDS['IKEv2_enabled'],
  CISCO_WORKAROUNDS['aaa_auth_listener'],
  CISCO_WORKAROUNDS['CA_Server'],
  CISCO_WORKAROUNDS['mdm_proxy'],
  CISCO_WORKAROUNDS['ssl_vpn'],
  CISCO_WORKAROUNDS['proxy_bypass'],
  CISCO_WORKAROUNDS['mus'],
  CISCO_WORKAROUNDS['rest_api']
);

workaround_params = {
  "check_anyconnect"  : 1,
  "check_no_shutdown" : 1
};

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvg35618, CSCvh79732, CSCvh81737, and CSCvh81870"
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_ranges);
