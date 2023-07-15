#TRUSTED 6204bd3d4129f0e5509419696651a07a1f5c97f49ce6def8dc024d3a77e06cbb70b538c5055631d5ae1dea24a663cc1a075c25faf645b244268072d97a8fddaaa66169eb5d0ab6432325c6975e4ff31128642796adb2781d0150616ff960ffcfcc86b8c7804d244afeb7facb3d0b07f51b0e2e510abb31f924cfaf5288393bca2944559596be50006cd6f636cfd57e0f07ae7167cce8b189edfd54b95b57fd81664d465c338a56af534ed3cd1378b0a03e2f5d4f9d4d90a5415dee590b16922d204e23c617cee153883b0cb536e276445c4c8c644f97be46ae64d2e0ffe4ecfe260f22a0f8bd463de966c6e471602d08c49b353055100d0b52719dd2692156bd15ce0cd484acd633a11e16ad200adb165fb108ab2a86fa3be9cc0bfd5fa028b934c365cfa8446c4e987c9c8a0b0af5916ae59034943b769a372d354a8f78fe5ca15960cb50ce055e7e872de909c40c1c24a9396b7f9fd1635f31e7bed8587370e6e7a1984d47b485b4343f04079f4734b990c93923d5e60d65945b771d82e4881cb880716851d10fca5df021b0851d29b64c51e9015cbfec78e48334ac487a576ab62ca7d6562549bddd0db4d4958810fd0516ffb4bbab48eb867432f8c28386788ba019efbbf8df9d58a085a8e365a7023b27a052010309594413b6fd75b71af35dcc4af3f6f384ce6495fd9f6e740795cd4c41de5acb486e78ceb65cd9a6aa
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132751);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/06");

  script_cve_id("CVE-2019-12637");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp98834");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191016-ise-stored-xss");

  script_name(english:"Cisco Identity Services Engine Multiple Stored Cross-Site Scripting Vulnerabilities (cisco-sa-20191016-ise-stored-xss)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A cross-site scripting (XSS) vulnerability exists in the web-based management interface of Cisco Identity Services
Engine (ISE) due to improper validation of user-supplied input before returning it to users. An authenticated, remote
attacker can exploit this, persuading a user of the interface to click a crafted link, to execute arbitrary script code in
a user's browser session to access sensitive, browser-based information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191016-ise-stored-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3c5b60d5");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp98834");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp98834");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12637");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

vuln_ranges = [
  { 'min_ver' : '2.2.0', 'fix_ver' : '2.2.0.470' },
  { 'min_ver' : '2.3.0', 'fix_ver' : '2.3.0.298' },
  { 'min_ver' : '2.4.0', 'fix_ver' : '2.4.0.357' },
  { 'min_ver' : '2.6.0', 'fix_ver' : '2.6.0.156' },
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

required_patch = '';
if      (product_info['version'] =~ "^2\.2\.0($|[^0-9])") required_patch = '15';
else if (product_info['version'] =~ "^2\.3\.0($|[^0-9])") required_patch = '7';
else if (product_info['version'] =~ "^2\.4\.0($|[^0-9])") required_patch = '10';
else if (product_info['version'] =~ "^2\.6\.0($|[^0-9])") required_patch = '3';

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvp98834',
  'xss'      , TRUE
);

# uses required_patch parameters set by above version ranges
cisco::check_and_report(product_info:product_info,
    reporting:reporting,
    workarounds:workarounds,
    workaround_params:workaround_params,
    vuln_ranges:vuln_ranges,
    required_patch:required_patch);