#TRUSTED a54f13b79a52e184a3abc98ce03f3b2d9547989dd814f176959237bcae0d4a0fbe211b83c2a5b7818fdd1d240cc1ba9cd4c95261862041dee04cffa332ab591aa2b1862d64b1b6e8dd0cb265e3b2aab8fa6a5b2682c0d546bf2ac54b770f17b4a3422cb4cc51afd6461eee593e49ae03735a65d37c78b838ad186592d6da968a8f2dc84c583729a22544d5e30db3a1e64add89bbb4d8952da6e901835e0559ed3bb85df2962487699bc803ad04bdbc0cecaac28da17e157c8b94b6f3a6a3986211326430b6bfe5ddc76b3ca6cc5aadaf1b122fb7c9919636f13f3d25fcc9b63653049754cf056b44c5f73e2b5106e59cb127ff8faf64f7ea265b239bc06c715497b7a819406a5999c04bca406232177ba600622bd4494621a9eab2b9f668fac08e728dbe1323646c7cce90190b2bbfebd483600cb4034924d7214f663e373dfe958418502fdf1bc6ac2ded7772c186ce128bb2c1100447605855f37ea43489dfa23d5824f6535d6d3e354c47fac6cffc07102b30da122bf609372485c62c726e2c17dde5463559b4e5b896ffc0374b6dc3412a1a4406fa4ffedd45fa5e710112d11c13993d2d2e7febcd543332ec46df13c8599cb8e6d32722ea58b46b12e5af565b9bff7e7c4b3a4b3b2a3756a301280ebc6242181926b9b2202f3ffbfbf773806909f27d125016c8e49a37f6631847b49cadfeb6698641e4282ae54f635e3c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104662);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-12337");
  script_bugtraq_id(101865);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg22923");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20171115-vos");

  script_name(english:"Cisco Unity Presence Voice Operating System-Based Products Unauthorized Access Vulnerability");
  script_summary(english:"Checks the Cisco Unified Communications Manager version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Unity Presence
is affected by one or more vulnerabilities. Please see the included 
Cisco BIDs and the Cisco Security Advisory for more information.");
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

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_presence_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/UCOS/Cisco Unified Presence/version", "Settings/ParanoidReport");

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

product_info = cisco::get_product_info(name:"Cisco Unified Presence");

version_list = make_list(
  "8.6.1",
  "8.6.2",
  "8.6.2.10000.30",
  "8.6.3"
);

workarounds = make_list(CISCO_WORKAROUNDS['refresh_upgrade_or_pcd_migration']);
workaround_params = make_list();


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvg22923",
  'cmds'     , make_list("file view install system-history.log", "file view install install.log")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
