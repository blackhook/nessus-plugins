#TRUSTED 1184b5116812577b008c4ea7c0195bd20a2855aba64d4cedc1833866117e1924367b9c0bf9e21e8c2f7c4a67f99ad7b30553b4fa8a277d2f9a03f1bbf1e5a7e7e6b8e662f073172dd869a52da6a3724b1a0a0dc884eec09a32038c203522f0ab81ef62d8f20445a06d34f79e6401f51577f7b8126e77ac140fc231dc7adebb82c10ab3708977841690eb24a3373f24d85de8da8f15845a010d47d89c093f2640ec3a9a1cdf05eee4d9b89ad1e7be23ce782bfea17b489120b546f2b23fbec653a0184da28a54604d9b1e0b654f75813803b35b39abed9da3fd9ce10763ebc409ab161f6f1e794b049f521c29d8d1b84fde7249a5b25db8d25fb74866fefbf794f8f8b1bdfe9e5215d51a15a623f0354c0391058f8fd94fd9566172752d358fe4241ebe45c31633c86aa81be5b994c93268b265fa5c98693992fba0e9f735967b505ffd528e4c226a3958ace2bcedc1bb9ff604231ab8d63968b1540cb8c95757375a62fc3392ca76218007b66b0897ff6feb7ae79a3b60f2af948ee122b555bfdd98bf36eaca92d16e120e5cde9d5d499015f0ec527f65762a5b1b3112cc915dc5be690bedefcc64270c454955648fcc29630bdce6462edbfa41b5a17caf10da2295f430582b24fd3b262e6d9e4211974b96db90e973bc260a8ae08b5033c6807800cd5d01587438ad0e8e13d67424f93ab05a1ed437b082133df1511c6fcac5
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110565);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/06");

  script_cve_id("CVE-2018-0289");
  script_bugtraq_id(104196);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh11308");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180516-ident-se-xss");

  script_name(english:"Cisco Identity Services Engine Cross-Site Scripting Vulnerability");
  script_summary(english:"Checks the Cisco Identity Services Engine Software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Identity Services
Engine Software is affected by a cross-site scripting vulnerability.
Please see the included Cisco BID and the Cisco Security Advisory for
more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180516-ise-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?32f7d3e4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh11308");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvh11308.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0289");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco Identity Services Engine Software");

vuln_ranges = [
  { 'min_ver' : '2.3.0', 'fix_ver' : '2.4.0.357'  }
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvh11308",
  'fix'      , 'See advisory',
  'xss'      , TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, workarounds:workarounds, workaround_params:workaround_params, vuln_ranges:vuln_ranges);
