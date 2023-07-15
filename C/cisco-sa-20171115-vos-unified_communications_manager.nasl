#TRUSTED 9f5d75ac2fc55fee6e55dc812e150bc88cfee609d00faadc374cf1ef78ac05ebb1aea7a61564d33c50f5a3cf51da7fed6faf99fd3bfd3e47f9e534f680124cdea1498e958bfee81477773f49ea2f7b6a4b7a7b4924ee5c7df45ec093e1638f778d8fdb46ce5907befb92b20435f4585f60ab7d060900e0e86f4d1fcdeb19deea8b51a2efd9c714c68551948d42bb67007658be1a3dad768aaffac45d6e80fa13c7e9af79255072242cc77b5069b6f08f95077b9e883407aa09d6b1151ebbd469d335331e53570657a7c4311274203d21402f17a47d1bcf9decc982ce03860c9fa2a902ae17f01f10953660a31c0399cceea238d2d1ab78c6cf1615c1ccca00f6a2440a8f58d1ddfa9a3aace75ff023d28eba6975b684fb979f2b18bbfed2a4f0146ee1ddb7740c60f13d19d5e5927392f1126b8503da7c33a16573b99bef7b9e1227bfb067f20d3bcc93ef48a950264fecd95cb96d22eaa462cca4407f027a941f751557c643fe7a28640009049bd8ae73ec9ed2c6dd2d1cee8e5b5f494bdb408e2270449c7f2e0a01c56afdd80b6c364159f79b5c68de0948d52467d0c3d83ec014e12c0a796a9d5783f2fe7e4ca5b114547de53147b7be6d64294ef5cbe974f8bf3e3c71ee40d948d502bb50d208763c384d74d6428aafa305b64ea94d234ba9d43048cc251d5b21eabcc81db5c10bbda3ec63d29edb0a57eaf37dd069a86c
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104661);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-12337");
  script_bugtraq_id(101865);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg22923");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20171115-vos");

  script_name(english:"Cisco CUCM Voice Operating System-Based Products Unauthorized Access Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Unified 
Communications Manager is affected by one or more vulnerabilities. 
Please see the included Cisco BIDs and the Cisco Security Advisory 
for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171115-vos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3e2c1cc2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg22923");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvg22923.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12337");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");
include("global_settings.inc");

# Setting to paranoid for the following reason:
# If the vulnerable device is subsequently upgraded using the standard 
# upgrade method to an Engineering Special Release, service update, or 
# a new major release of the affected product, this vulnerability is remediated by that action.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:"Cisco Unified Communications Manager");

version_list = make_list(
  "8.6.1",
  "8.6.2",
  "8.6.2.10000.30",
  "8.6.3",
  "9.0.1",
  "9.0.2",
  "9.1.1",
  "9.1.2.10000.28",
  "10.5.2",
  "10.5.2.10000.5",
  "11.0.1.10000.10",
  "11.5.1",
  "11.5.1.10000.6",
  "12.0.1.10000.1"
);

workarounds = make_list(CISCO_WORKAROUNDS['refresh_upgrade_or_pcd_migration']);
workaround_params = make_list();


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['display_version'],
  'bug_id'   , "CSCvg22923",
  'cmds'     , make_list("file view install system-history.log", "file view install install.log")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
