#TRUSTED 709312a5ed73872b009f6b2263346b25a5ec90e5142e7d18b61d026df830a8bb454fab4b99438081635b694b7036a618074d791042d3f37fb195042c4895242bc3e2c7b749d7a38f45fbdac3e3c16d708260c72496dea073233dd021008bb7b9d3c42f76c07f79622371fa599339d008c84613fe3fccf656f6725e43bd728e763bc097bc2634daa40c6ce5a8fbee6bfbf290f2a6576496f9f4e19184072f48f54d9a994068c1a1090e715796324a32e9c7e7326eab43f41253ffd246d6e0e28b594a4ef64d25282018d0056532cd24636851181ebeaab1db1bdd3935a5f51c09e4eecb5f6f4efbf121ba1360c5ffb17701895171e927423550ec8c51d537fabe11c7811f2b093b85a33cbb92b3f86863ae2fdb4ad3393c6da903c860289709e2803db2b3ac794a6030787222ef5956ff52b63e095124a3271a07ce96bd3fe63376aa30faa8d94f56994e655499b179ae9870d8099c62a26c5955ee5e344e127474e45ff509d260059a50d997931a385477c892c51f4898a6bc4baf8c90bc233344ceca0bf3f2484602fbfd41cb8bc7cab915b32b47bd2929952fa11cc284028ff39fc3a8a4a58498f43b8291eaee8f43fd4958a9cbe70d7382458690e00a5c2ff87c030be0c771ec864e2143a1738a5c009c91b7b32063c15dcebcebaf58b4ae2ebae64cf23fcb240db93e0359d62fc5a47cb238045f41480f6516acf3a718d0
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104663);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-12337");
  script_bugtraq_id(101865);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg55128");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20171115-vos");

  script_name(english:"Cisco Unity Connection Voice Operating System-Based Products Unauthorized Access Vulnerability");
  script_summary(english:"Checks the Cisco Unified Communications Manager version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Unity Connection 
is affected by one or more vulnerabilities. Please see the included 
Cisco BIDs and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171115-vos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3e2c1cc2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg55128");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvg55128.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unity_connection");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_uc_version.nasl");
  script_require_keys("Host/Cisco/Unity_Connection/Version", "Settings/ParanoidReport");

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

product_info = cisco::get_product_info(name:"Cisco Unity Connection");

version_list = make_list(
  "8.6.5.8",
  "9.5.0.9.TT0",
  "10.6.0.9",
  "11.5.1.999"
);

workarounds = make_list(CISCO_WORKAROUNDS['refresh_upgrade_or_pcd_migration']);
workaround_params = make_list();


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvg55128",
  'cmds'     , make_list("file view install system-history.log", "file view install install.log")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
