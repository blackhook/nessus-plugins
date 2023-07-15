#TRUSTED 4b20971199f167c8e27fbeb51323576883c32c5acdfc15d3c290d36711614d81c7c60695a23144c8209ded283db7a53f31c5bcca8bdcb8748abbb7cf330beab41f10467ea05dc7b023e963de453819fc8ca31a321a04ca5613e7cb5f52a39b944f8d335347946916fbe546b66bf274b51530164dc8ea3649af20b0a7ce0f13c17b97fd1517c2250274aa720ba4bcd756666e03881bd6038e57abeb3cf2003a7e862441d34779d0825be31d7889e32b015f7ebd54c0eab22ad28e79f53ed2f09a90ee593bcbad1cf12ca59ef06c4861010b84ef7115ab245fc94b78d0e3e08c1aeb1d130d0808c721e61916f250d6630d1b0bd2f509badeeef597278e3d8587a0f596416a50f108aa7bec81e16c3da5d1b2dd763c3f4d7229531137c887e77535144d63c84a61d40e047afe5e97223a27e90cf97e72bf4c24bd21bf58959b246574e51767355a9f0a225dc4c98fd1f6c1bd8ebce93a5d9e730a3708d605a05b2bcf05da27a39fe046140c265f668901a10c1ca8923b30fb7e6073e5e7f3eef71d5018ed03daa6a092663cbfc442d2abd4fcd46e70a6819f5e4d27a16157ee45f744e600f9222bf206c9a84c8a8f16d90f30b9fdeba75e72ceff2d15fe230b7ff171dbd5a8aae1adf117922b368bab31da5317375d203f56eaac1d3d004eee2aeae0c23c2b0da91076913e2aa66160060a5ff6ce8ee09e60d51a2295e3f006e6f3
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(152213);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/17");

  script_cve_id("CVE-2021-1602");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy02232");
  script_xref(name:"CISCO-SA", value:"cisco-sa-rv-code-execution-9UVJr7k4");
  script_xref(name:"IAVA", value:"2021-A-0360");

  script_name(english:"Cisco Small Business RV160 and RV260 Series VPN Routers RCE (cisco-sa-rv-code-execution-9UVJr7k4)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-rv-code-execution-9UVJr7k4)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware is affected by a vulnerability
in the web-based management interface of Cisco Small Business RV160, RV160W, RV260, RV260P, and RV260W Routers which
could allow an unauthenticated, remote attacker to execute arbitrary commands on the underlying operating system of an
affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv-code-execution-9UVJr7k4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1b0c0e19");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy02232");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy02232");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1602");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv160_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv160w_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv260_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv260p_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv260w_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv160");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv160w");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv260");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv260p");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv260w");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');
var model = toupper(product_info['model']);

if (model !~ "^RV(160W?|260[PW]?)")
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series router');

var vuln_ranges = [{ 'min_ver' : '0', 'fix_ver' : '1.0.01.04' }];

var reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvy02232',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
