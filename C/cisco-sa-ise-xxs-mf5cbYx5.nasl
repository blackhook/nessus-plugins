#TRUSTED 4999ae4aa8de92f9151ee42dcd891d6b7486e9b7d233f2a76f25f814bfe01a36d403debe1967fd28cc30291cea8c8bcd39399ff7788a8a1fdf643e501724e0954ee57e442644189b8823999e647d48ee498b119649cc38362821dea14c5b02e90739cd9aa6c7db1a70b907ae822f015e83a2e3e4781da17beaa000206d68aed15571f0a6113f2b6304a185e1753dd44eaa8baec62fabfeff402cdcffb47b217fe80a1d5be9cb62fc639c59cd82b40bdc752ce6240bbba586c0823b66a4c1d1c49017865e28367dc0b406a9b5772bf882f231a3cd6f2419cd3893baa327d8e442ebe49de808c3ded60fdd6732140a62d4e7fa0c38bd356335f87b7fd3e7fa8ee50139b9ba18662253a7fb78e61e952afdf0c7b9110e2e28af8f0aeb0ea7c1d08558d1fd72884e5c9a8259af727fe58086910e675c7325915fd59e4b97790a1a41d3fcfbffac4d0a97616e15906c6adac94a0d89803f7fba5b99fb939614526e9cfbb33c5c92c2a21fb584c1f0ed75e56833f7708d60237072d1db70d9a3d769fa50e42cb899800c613ada86b973500480891c692dad3e4625e2fc070995d920abdd01bc2fb54c68271bf2d32019b6653f7c884ddcb286c493a15206b27f236da57e1c2357d42a8f4ba82858723186ba27681e9a4c2458f4f9856ac23934c38011e2119f970cf312b24b1829a50bc1e0847f85f8e138cdd3ad9a24f436c54e3657
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141354);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/22");

  script_cve_id("CVE-2020-3589");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu33884");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-xxs-mf5cbYx5");
  script_xref(name:"IAVA", value:"2020-A-0450-S");

  script_name(english:"Cisco Identity Services Engine XSS (cisco-sa-ise-xxs-mf5cbYx5)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A cross-site scripting (XSS) vulnerability exists in Cisco Identity Services Engine web-based management interface due
to improper validation of user-supplied input before returning it to users. An authenticated, remote attacker can
exploit this, by convincing a user to click a specially crafted URL, to execute arbitrary script code in a user's
browser session.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-xxs-mf5cbYx5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c0dddbb6");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu33884");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Security Advisory cisco-sa-ise-xxs-mf5cbYx5");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3589");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

# Affected releases listed are:
# 2.2p16 and earlier
# 2.3p7 and earlier
# 2.4p12 and earlier
# 2.6p7 and earlier
# 2.7p2 and earlier

var vuln_ranges = [
  {'min_ver':'0',   'fix_ver':'2.2.0.470'},
  {'min_ver':'2.3', 'fix_ver':'2.4.0.357'},
  {'min_ver':'2.6', 'fix_ver':'2.6.0.156'},
  {'min_ver':'2.7', 'fix_ver':'2.7.0.356'},
];

var required_patch = '';
if (product_info['version'] =~ "^2\.2\.0($|[^0-9])")
  var required_patch = '17';#  2.2P17
else if (product_info['version'] =~ "^2\.4\.0($|[^0-9])")
  var required_patch = '13';#  2.4P13
else if (product_info['version'] =~ "^2\.6\.0($|[^0-9])")
  var required_patch = '8';#  2.6P8
else if (product_info['version'] =~ "^2\.7\.0($|[^0-9])")
  var required_patch = '3';#  2.7P3

var reporting = make_array(
  'bug_id'   , 'CSCvu33884',
  'fix'      , 'See advisory',
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'xss'      , TRUE,
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);
