#TRUSTED 5141635e3ba8cbf9672064ed331ef27f90909b89a776abce281c121a92c00ac3517fe6f5bf2627ce3dec71e97416eefa2347dfda4e13acea7619d3248c5d13da62b6ddaf3dacea042ec49752053f031e55923ed0a067da6d6b3a0c86f3bccea5fbeee6eef5395ae36a24b925d4c01cdde8c1d87cadeccf2d670ff1f723b1e7f5ef8bd8d4c1273b32f284a720f06576ad255359853a452c427c472b0e43e1fbca2e20bcb5681e5a9d5d15288ce0f912632e45e177afa2cdfcbe2d819dcd7872e8c5d1ecc66519baaaab68dd94eff3de19dec3336395b4375e5167ece647be6ed7c519f1c84db45d3b0808c0bcc330530f95a5da91e7da09d3fcff88515d99365bb4aa94121be51c183d0d6973f9a1ecc4b8f72b043b70a14c704af666723f8baafd89afd3b007a173cc4f288fc1acc70b10f426989154b8099ed59962a501e78203f1ca5922f10d31d25ddc22cccf391321df491f34fe901e0dbab3c18aea09d8f52a43d33fa30b0fe3db18f739b7d1e30b534e66b3740ab865e22daf8ad80e53583e15140310e0d710b44095ebacfab452153a261263dc06f65a498c25d79c11721d34a6865e973a6c12bb6b13e4246b5e839ed9f2dfec29adc97fc79cfffe36d285afb31fc3ff1c41cc312cec9f55643d18d567dbea61cd5828e7cc83ec230c59811db8b1cc5cbe5d6308a489fe9cf513270aead900bd8fdf16cca1d183a5d4
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149847);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-26082");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv38679");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-zip-bypass-gbU4gtTg");
  script_xref(name:"IAVA", value:"2020-A-0447-S");

  script_name(english:"Cisco Email Security Appliance Zip Content Filter Bypass (cisco-sa-esa-zip-bypass-gbU4gtTg)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Email Security Appliance (ESA) is affected by a vulnerability in the zip
decompression engine due to improper handling of password-protected zip files. An unauthenticated, remote attacker can
exploit this with a crafted zip file to bypass content filters.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-zip-bypass-gbU4gtTg
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab126d2d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv38679");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv38679");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26082");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:email_security_appliance");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

var vuln_ranges = [{ 'min_ver' : '0.0', 'fix_ver' : '13.5.2' }];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv38679',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
