#TRUSTED a8a24fa037f5f92f78ccf8f11bea4297c685ef6064a3fbf4641e86088f1df54069dc20dce137d7b79ec481e46e542f35b83e8bb089aa9418887ec5ab3684b48e392f16d80c29590b3c8ec24401c96b5c34d3bf9bb446c4a0bee7a704799c10fe5c317847c49db1952be539ddffece8ffda7ee7fbce19d8cdd63b5972606a3db1d7ec670cf8cc0b895b89e305cc2b9441d4d4399fc1f73dedaf709e63bef8f10637bb1593763daff9809c2190ffd290c358241e94eab41f8f8758dbd6b007e6a93542804baf2f83b995fcfa301e1ddd673cc43a3cd1b0804065804e35aca8d6b069348ece04f64bb39d98b4f5f0e6293b22170f35d605a62e610db70c739ab472d42d6ba91d15c89d86a9c43ebf2593984ffe11e964b97597353a92bd6decc5949e7755b48da9dab05286cba325df7b43b5189400a61393470783f4ad70d805394f206ad2be98d2522f804e6855a9122dd451aa1538aecfcca27deeee6933f109f9b917a5910f17fb1d71fd2277130c977aa91fe32af7271ba6f41597483f2680d59b7427d3dbca54ed6d8863a237d3448cc5aedf9e41361d7bad1b856edc840e7708448da73163d8678289efcd92e202be89126bca074315486cbf8a467095a467be0ca220f0da14df4389922ecbc4a089338b45bc3aebfbc053ff130b13d1832cc85e3b4ec87e17623c46f995c5e0e540ed53185da364f8835629e14265352f
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147759);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/16");

  script_cve_id("CVE-2020-3385");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs72674");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vedgfpdos-PkqQrnwV");

  script_name(english:"Cisco SD-WAN vEdge Routers DoS (cisco-sa-vedgfpdos-PkqQrnwV)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vEdge routers are affected by a denial of service (DoS)
vulnerability in the deep packet inspection (DPI) engine due to insufficient handling of malformed packets. An
unauthenticated, adjacent attacker can exploit this to cause a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vedgfpdos-PkqQrnwV
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e3e3149");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs72674");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs72674.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3385");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:vedge_5000");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:vedge_cloud_router");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if (
    'vedge-cloud' >!< tolower(product_info['model']) &&
    ('vedge' >!< tolower(product_info['model']) || product_info['model'] !~  "vedge.*5(k|[0-9]{3})"))
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver':'0.0',  'fix_ver':'18.4.5' },
  { 'min_ver':'19.2', 'fix_ver':'19.2.3' },
  { 'min_ver':'19.3', 'fix_ver':'20.1.1' }
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs72674',
  'disable_caveat', TRUE
);

version_list = make_list
(
  '18.4.303',
  '18.4.302'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  vuln_versions:version_list
);
