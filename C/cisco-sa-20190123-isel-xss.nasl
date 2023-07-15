#TRUSTED 9d6b347275384c803bb8bd9a2728764dc806c0d5e82ea220cac2c9908ee3d2666df7ba7dc6d4c1fd8250cfc56cd1cd5f7ff3a0ed81e4c7666a199e47f45d2a0b61fb9d50b849017ff80dfc2509cb4bd153ad53d261cbade4bda1403ee7dd2d9f8433b952fc05d07a54cc08ca23e4c9f41a008ace41f40f87f11331dd34f899cbc117edb40158320f5b3d5661a1f6ac175214e38dc73ed5f1249ca8e6329bee454bdef31feab18f9b6d3c5669146bebbf3635052b299505078c82889e6e84c45a6f32d1c8f0cae1d94098a4f6d8c575a48fd35446979113eede86e19fbe91ec5d447c2e05c31be826b4be8dc2cd8c5916e0dd59dd7b162a944a53a188bbaa0c7da6c1bb7cb76a71fcc2bf442866119778b12d69cbd76c56c0931ff08a4100cc57b38890ca6bff9e09ad30f7fbb4bfa3674e927da72c320cd67b2cd7fbc311827932a0e0db8b98a4c1beee446cf9450808e4d67f53ff060b3bb42cc07e9e04326dcfb66e586d08f3679a153cdf082c5c5344fa7a93e4377a6467fd503cc0e323bfb0466f93e3cf9fa684ddb398f86517d6f508d529f316b298502e91800e525594c51737ad332ef9268f902af06c106afcd28def1c92ef423adc5ad1b613981c7423e97708782a9c5d84dde44dc803a5a71a2fdedfbd07dd555c090d94c0206a5112984fc7efae0f1b8909269fe6337445fbcdbf337e471083f1d830068a00a2a4
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126104);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/06");

  script_cve_id("CVE-2018-15455");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm62862");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190123-isel-xss");

  script_name(english:"Cisco Identity Services Engine Logging Cross-Site Scripting Vulnerability (cisco-sa-20190123-isel-xss)");
  script_summary(english:"Checks the Cisco Identity Services Engine Software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine
Software is affected by cross-site scripting vulnerability in the
logging component. This could allow an unauthenticated, remote 
attacker to conduct cross-site scripting attacks. The  vulnerability
is due to the improper validation of requests  stored in the system's
logging database. An attacker could  exploit this vulnerability by
sending malicious requests to  the targeted system. An exploit could
allow the attacker to  conduct cross-site scripting attacks when an
administrator  views the logs in the Admin Portal.

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190123-isel-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42b2008c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm62862");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs
CSCvm62862.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15455");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco Identity Services Engine Software");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

vuln_ranges = [
  { 'min_ver' : '2.2.0', 'fix_ver' : '2.3.0.298' },
  { 'min_ver' : '2.4.0', 'fix_ver' : '2.4.0.357' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

# ISE version doesn't change when patches are installed, so even if
# they are on the proper version we have to double check patch level
required_patch = '';
if      (product_info['version'] =~ "^2\.3\.0($|[^0-9])") required_patch = '6';
else if (product_info['version'] =~ "^2\.4\.0($|[^0-9])") required_patch = '6';

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvm62862',
  'fix'      , 'See advisory',
  'xss'      , TRUE
);

# uses required_patch parameters set by above version ranges
cisco::check_and_report(product_info:product_info, reporting:reporting, workarounds:workarounds, workaround_params:workaround_params, vuln_ranges:vuln_ranges, required_patch:required_patch);
