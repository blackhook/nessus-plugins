#TRUSTED 6fbce208e66977c4eb806c6dba6d39e1972ef4e2b12fb2f872e04387675ceed72d9dbc9c30636f712790d1727d58a7fe4464aed8057e1d5ebf2a6d041c8982fe940bd284ab1e39531cf6b2ffafc864c8c47b50c1cbe8e760206149cb9a5fb6be5c03b98fbc0e84dbe0c4eac7caa62a9f77ec03bc685ee0bff27672d7a86040948c77feffbb87edec9af3ba7b563eeacf5e0d33b7184be8cae9fd014e12da6189a17401c1ddeff627130255c5357deaeb21a690aea05a7ee1593060de85f917bf5efd0de5a88bdbbb111cd3dfa64d3063b33046e4e043dfa1871e370b74558c3c81077a430f71c1c675bc1bb5eb6929d47b67451e4de0a99be5c4d74ee4ba7a93148d53c40ad3f689f42eb506a7381f3c1aa3c8ec886bff48c2f2941bb4a8dd767995a5103d32c03e9fe77756d6b97a4a2f2cd560c716f6214cb5f95d683995d2391ae65aed2b5ed750f8264b2207852e9a831f274f632e2fdf6c25ceaa0468c2cbab6624001c30d3d2e36c89e7cc0df0c9ec9cddd7bd2a8e45adc516500c545a9ca6c8b8ea59ab06395b02abcd7b573f4e85424a354f5e880bf8c16aeae4adcc41edafdfd99e7cd45174e835619395f2ba0e3c1cd3303afe2e1e373b64d97c1a5e6ec0bbb759ae01267d2592d141396ca3aad8726e01ca19bf0f605cf537831d747bce64bd07129feddffb7a1d665ac172b08fd64dda8242cdbac8491e9e379d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128761);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/06");

  script_cve_id("CVE-2019-12644");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp98851");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190904-ise-xss");

  script_name(english:"Cisco Identity Services Engine Cross-Site Scripting Vulnerability");
  script_summary(english:"Checks Cisco Identity Services Engine version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the web-based management interface of Cisco
Identity Services Engine (ISE) Software could allow an
unauthenticated, remote attacker to conduct a cross-site scripting
(XSS) attack against a user of the web-based management interface of
an affected device. The vulnerability exists because the web-based
management interface of the affected device does not properly validate
user-supplied input. An attacker could exploit this vulnerability by
persuading a user to click a crafted link. A successful exploit could
allow the attacker to execute arbitrary script code in the context of
the affected interface or access sensitive, browser-based information.

Please see the included Cisco BIDs and Cisco Security Advisory for
more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190904-ise-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0e2b423a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp98851");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp98851");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12644");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

# 'At the time of publication, this vulnerability affected Cisco ISE Software
# releases earlier than Release 2.6.0.' - Cisco
# advisory updated and Release 2.4.0.357 Patch 10
vuln_ranges = [
  { 'min_ver': '0.0',      'fix_ver': '2.4.0.357'} , 
  { 'min_ver' : '2.5.0',   'fix_ver' : '2.6.0' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

required_patch = '';
if (product_info['version'] =~ "^2\.4\.0($|[^0-9])") required_patch = '10';

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvp98851',
  'xss'      , TRUE
);

cisco::check_and_report(
  product_info      : product_info,
  workarounds       : workarounds,
  workaround_params : workaround_params,
  reporting         : reporting,
  vuln_ranges       : vuln_ranges,
  required_patch    : required_patch
);
