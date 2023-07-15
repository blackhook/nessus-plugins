#TRUSTED 516e47f1252747d7aca5523798882774caf34404e5a451743a87f700a9babe0406298c87895561b9fb07f812f7c57e89bddf458dc97ce3ed371734be27b280b00134a7508cffa486b4a37d2b5caccb623642d3e7daccb7e866b9d09db737469fe069726ca84d6da1c3e1df47a60fe18221e2ca158f5a894937155b930765792a86c187ae8a345c3d40339439a339c02b32391be4f701bfffe60e18463848a956e0261330d1e1b654e32d7da4fe71b87159f3414d0965226ea167bfcbf40304feaf6e9e53dd8448089c7f30f129cf1ce6a28c7aa71f338b3cc3ed80ee69316cf47537c4b05fd892ab51ea56df853213f763ae4f8b0bad01920494b2969860f8a0c7ff26826b1b989a4f8f92dffe829cac23cc48e0cdb92f4f518a0dec9159a042aaf9afdb3fb416233f041cb88a2a5f15ef4d6f1c7167abe56ae1ac3791b02d06f4134e6f0be3cfc9e52b50383190cd608326a7f62df3a884b2e1c629180c57d63bff166e306de0010cb3f48717b2de30d58065cdd693d0d0450b8ddff4ae1b113190ac3ef7496eb8b1f4b6eac53bd253348d04100afb6df284473009b1bc707704d5fc1d4885e1f795fc2636f4b4faaace38218481699397b6016cb201d87760859f5ba8c291595d5ca9ec0a6a9577768def8f0224c768568109791eeaffe737358faf36b894d1eff917c9c9bd31a3e9fc3a80baac1674091f3dafd0133c70c6
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110566);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/06");

  script_cve_id("CVE-2018-0277");
  script_bugtraq_id(104212);
  script_xref(name:"CISCO-BUG-ID", value:"CSCve31857");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180516-iseeap");

  script_name(english:"Cisco Identity Services Engine DoS");
  script_summary(english:"Checks the Cisco Identity Services Engine Software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Identity Services
Engine Software is affected by a denial of service vulnerability.
Please see the included Cisco BID and the Cisco Security Advisory for
more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180516-iseeap
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f4e9309e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve31857");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCve31857.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0277");

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
  { 'min_ver' : '1.0', 'fix_ver' : '1.4.0.253' },
  { 'min_ver' : '2.0.0', 'fix_ver' : '2.1.0.474' },
  { 'min_ver' : '2.2.0', 'fix_ver' : '2.2.0.470' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

# ISE version doesn't change when patches are installed, so even if
# they are on the proper version we have to double check patch level
required_patch = '';
if      (product_info['version'] =~ "^2\.2\.0($|[^0-9])") required_patch = '5';
else if (product_info['version'] =~ "^2\.1\.0($|[^0-9])") required_patch = '7';
else if (product_info['version'] =~ "^1\.4($|[^0-9])")    required_patch = '12';

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , "CSCve31857",
  'fix'      , 'See advisory'
);

# uses required_patch parameters set by above version ranges
cisco::check_and_report(product_info:product_info, reporting:reporting, workarounds:workarounds, workaround_params:workaround_params, vuln_ranges:vuln_ranges, required_patch:required_patch);
