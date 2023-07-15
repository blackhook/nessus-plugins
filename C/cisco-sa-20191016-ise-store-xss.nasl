#TRUSTED 63ce1028b2a60bd3415476ca8e023c76ccf78cdedc5282b7bbfa47a0b8fa7ad6b17f07eb45046de0c648008fa8b66344806f735b9698ea70f1adc264e99c7f242029c9af0fe2c596a7418fdfcafcf0daa938f530cf0cc6f71102696f7adb424d70826171fa172efd0e88ecb571905fff9edbd37a933fb0a8ef40a1bbc58c0a0d5abd4d074f4bfeb01f9ea94fc5d66b8c5981a87b965d93cda76331cdd5d9c9ca52ae2e82f5fca7073ced5c218600728d114082c3d71a03941923b27b77edd3278cce57bad1728db63d7fbf4f5d89e5341b56f4634bdd656843137a61ee55f4b5c8a6744ca895c637c3b17a8446db5ac6ca0ed469e9ef3775dcf001007e982909117312afc9636666ce5c79fe5ce1b727966d56855f270c019d83dc9056535a1f0ca2909442621a77dd2a2f82dd939d3618052a29e9f611d2e30d93828759b8a4b6e8ab5c51359b084f414c642cb1aaf07adad689a1417d3a961d2ef83f1c6d34082cffd9af1c10129c2c8b799e28e86243b545bb8c0933fd862d961ec214a04fdb0c9d08964a96ff8b7889b5aa5b0041775eefd775971a7ab99fadc3576504f3b9a88dde5df5dad697a9c097aae82c3ca06afdff9dd9722653a8c4484dff88c97a0f0bd06a8bc9f164178fc2344a581384f643ed151f8050248faf0342cfe6bf785c967145f300271d22d22e6b5da69ecca3aebd58a819a2af6077acb6910e85
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132750);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/06");

  script_cve_id("CVE-2019-12638");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp96921");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191016-ise-store-xss");

  script_name(english:"Cisco Identity Services Engine Stored Cross-Site Scripting Vulnerability (cisco-sa-20191016-ise-store-xss)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A cross-site scripting (XSS) vulnerability exists in the web-based management interface of Cisco Identity Services
Engine (ISE) due to improper validation of user-supplied input before returning it to users. An authenticated, remote
attacker can exploit this, persuading a user of the interface to click a crafted link, to execute arbitrary script code in
a user's browser session to access sensitive, browser-based information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191016-ise-store-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f632688");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp96921");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp96921");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12638");

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
  { 'min_ver' : '2.3.0', 'fix_ver' : '2.3.0.298' },
  { 'min_ver' : '2.4.0', 'fix_ver' : '2.4.0.357' },
  { 'min_ver' : '2.6.0', 'fix_ver' : '2.6.0.156' },
 ];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

required_patch = '';
if      (product_info['version'] =~ "^2\.3\.0($|[^0-9])") required_patch = '7';
else if (product_info['version'] =~ "^2\.4\.0($|[^0-9])") required_patch = '10';
else if (product_info['version'] =~ "^2\.6\.0($|[^0-9])") required_patch = '3';

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvp96921',
  'xss'      , TRUE
);

# uses required_patch parameters set by above version ranges
cisco::check_and_report(product_info:product_info,
    reporting:reporting,
    workarounds:workarounds,
    workaround_params:workaround_params,
    vuln_ranges:vuln_ranges,
    required_patch:required_patch);