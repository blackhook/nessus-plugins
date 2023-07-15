#TRUSTED 725f27640d64c17f105cb83ea0e846f786884f3e97965e9043e537d2350e2744b291b592ad83f619558723b2aef934ae29e17a39d155c0e0b6ba96b371b7acc16f67b7a7ce855d0bfc532300c0f642c0f9e6177b5a08cac285de7f0c7f4f4cbcf10ad049c1031ee8e4caf9a6a021f2f2951b77eac15a81eadccb80bd8a19e3bf4ab81d43f43fee7a997a6dc3fab26253fab46aea6725645e039d84ae3fdb3e7c8963dbd2c9d0d36e1d53e00de1bd4cddee23c983ea42ab6a07c649424f7974063d5902229d26e278e06222648d883d90a91208761c68ee5435371b306cea3c800b957a2ecae79904291877e451832028997dc9b61cf32feb2f871ea3bc82ad43d570defdfad82087e2b6b18c6735bcf23f812e1d7e8f69cd5bd0597807f9e0f453cfbb6ec6ed3380f72942e8fa7226db969f445a9dda1e9404c6c918cfb601613c033476c12f107f17d83a51fb81337fd02a744c7256349fbc9bbea24166677bd74ebaf60ed795807ab04c1be8167444d7b9ced551950b03f7b5f5d9a78c5ec73c2955d50af875212d868aaaae231af035878e84e24e3e06507a4f3aad8112cc0c7bcdfa95bb909858f7aca1ab7cb163a2f4014bf8b0c8802f17f58938ccddf8fa4dfd372179e477d4cf30be89199cb9616a769c38c493caf26bc07f0688a620cb2200669e4cdfdf642cfe539e61f060b4641e32040170fe888e0323352fd75f
#TRUST-RSA-SHA256 9cd09b3228627b314a39cb88a1a5d53be2170e9620e35cda1d2e8fcc7645576d944c26e719bbf8b15c758c3fd0df4b2a47d7aebc3604326304db3c8c829ecb71d3f655d67afdabb34634e50bdc3f63a5ea74306704354b04733079ff1881ebbf9fa6eb74132711e4c1acd284f23ce27e0c297aa83c0042a7000b02860e86d24c28573ad5d3d544448cac411fe3a90d6cb81aa7df2f7bfb9605ec38e82a00b62607a8d63b9074f4d9bb8ddb84db1d94a5ef4dfe511dd54f21f5afbd9e76b2bb2fc24389b6eaa21b1ba74d227770fcccee313edf8697ce6c8f94b3782a7053fa897b2a1566812cb16dd892f6faf016054842172b6d897cdbd1f5a8caf693fdc459e7a0bb5c954cb0f6e237a191893edaa1a1d81c9d4a93aa944b3189b0dc8709c3293c4f893f3957d308455682b5704618ebc3c502eb06a11a2d3d40673aeb11976ee62dde9d7cd6b56bab38d31780ad8d6ac767a6b4034b1c4fc402dcfbf0a64fe306cfe9c34d85269d9f3dbaf8dfb8aabc37dd879ac67ba7a2ca56868625edd428a5dd7988ad7662cf750c7383f1255838c27e122b888cf48efeb475a084a444e28961181ae6c16e79dfe9b39b40ce43d1b571ae0ab7a1c26d7a8376058cf47c29420a993207f092013729c3b040147ad9da9ebff88422c81914388353a05ead4d3cc813ebdadca5c5a743509534615d3a9fc7af2bfda6cf33b2c5c7480db213
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166914);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/29");

  script_cve_id("CVE-2022-20956");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc62419");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-access-contol-EeufSUCx");
  script_xref(name:"IAVA", value:"2022-A-0462");

  script_name(english:"Cisco Identity Services Engine Insufficient Access Control (cisco-sa-ise-access-contol-EeufSUCx)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services is affected by an insufficient access control
vulnerability. An authenticated, remote attacker can exploit this, by sending a crafted HTTP request, in order to bypass
authorization.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-access-contol-EeufSUCx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f3dbbfa");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc62419");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwc62419");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20956");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(648);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');
include('cisco_ise_func.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

# Only non-public hotfixes right now
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var vuln_ranges = [
  {'min_ver':'3.1', 'fix_ver':'3.1.0.518', required_patch:'5'}, # patch 5 DNE yet, flag all for now since no fix available
  {'min_ver':'3.2', 'fix_ver':'3.2.0.542', required_patch:'2'} # patch 2 DNE yet, flag all for now since no fix available
];

var required_patch = get_required_patch(vuln_ranges:vuln_ranges, version:product_info['version']);

if (empty_or_null(required_patch))
  audit(AUDIT_HOST_NOT, 'affected');

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwc62419',
  'disable_caveat', TRUE,
  'fix'           , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);
