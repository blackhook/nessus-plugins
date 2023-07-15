#TRUSTED 2d2211e24ca0caabd5e872eefb0a3a6e39d2c9576735538caa29fd5642b6fa050f9b3294f63528556b4828c5331a19b8fd573816f24a6fe1b1dc234e131e194f23814bb7c1589f2383def3bf036cddbf2e310fa6953a72598de2260178a1ce68394a9550624ba44b80d6716148788809201bfb4749fd831fe35fba89d10a0c7bcdcf7d255469b530b418497b4529cad420187cd60f0318bd4c190e46b141058ae23655629e9a402793131e576f600b23d3f2957095527873e12cd42aad3f8a30f3f1213908723dec46a3b9181bacf0e6c551001e3e5b93a60930fb8a9bdc1877f90630d671e0763727408905c91daf7da9244be1bfb26404d86650ab9bae5f398a7ae3a646c179dadeee9a309d6297e7e144b3b02925752d3850480a24ee77ffb7635b387706424397b13a915657ac5e0392e3d43b55dd4b532d5746830c1017516f0a5497bf2c352aed266f369ac35fea6e4974c50621cb98425036907084fc1c755f16fb966be9fa8d1e0e6ddd7ebf692052d22f31113e0d535b8ab70dab3e5d15d821d6737c6c50ea1c0d2409f012db94e31439b26382f6c0f0ca1b13fc19eb40aedaae169327975fb7e09daf26aef38198f089fe8d960bf2990aa9680fad4ed8eba447610211c4cf21ed80d311956ee42f26db6d99384f8407fc2263a2fae71f43b856b278d54866e0c1f865f4d6a32963a3f758891e00dbf872232516ed
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133651);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/06");

  script_cve_id("CVE-2020-3149");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs65467");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-xss-DxJsRWRx");
  script_xref(name:"IAVA", value:"2020-A-0058-S");

  script_name(english:"Cisco Identity Services Engine Stored Cross-Site Scripting Vulnerability (cisco-sa-ise-xss-DxJsRWRx)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A cross-site scripting (XSS) vulnerability exists in the web-based management interface of Cisco Identity Services
Engine (ISE) due to improper validation of user-supplied input before returning it to users. An authenticated, remote
attacker can exploit this, by providing malicious data to a specific field within the interface, in order to to execute
arbitrary script code in the context of the affected interface or access sensitive, browser-based information

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-xss-DxJsRWRx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?506fadfc");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs65467");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs65467");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3149");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
  { 'min_ver' : '0.0', 'fix_ver' : '2.4.0.357' },
  { 'min_ver' : '2.5.0', 'fix_ver' : '2.6.0.156' },
  { 'min_ver' : '2.7.0', 'fix_ver' : '2.7.0.356' }
 ];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs65467',
  'xss'      , TRUE,
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  workarounds:workarounds,
  workaround_params:workaround_params,
  vuln_ranges:vuln_ranges
);
