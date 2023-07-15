#TRUSTED 615b6b1c8fe93391959785245897951ee413c330d2dd975e412b9a6abae83ce41469768cefd3aeee95ccd4fcf4c4834373595495bf0a854abb1bb982d12070af2b5f4842a234129d069036ad5c6d8d4476cdb7c85d07096b79f11d3cf916785202255f2fc6bb82d130148e8848dbb432813e9eca6ed60a35543d0ad5745b0444e5f9104ca0d926f752d71a20819174dacb5035533777141992fe712a3421762c08bc5e697614ced53f2e6448c4ae09d03707ce33b7a5929280222ec0d3fea6872c56655af168ca48591d28c5045cbce795fa5f984b819e9d038701aa0e00a88ac9192c5962d4e57c3e53bf7d5805c9e91be67549849bf7c30107439575189b4708639192d7d40fd8f1eac108f312702baa33dbc9a4ea2e0c2dcd41105cbd2e53e39fe9b13ffe7dff218c313de34abe842970b335b9c91ab2f11f513b6c988f43e604592abce316d97df786323e290b11030566ad4916e279297967c4c935ef4fcf3dfe21dde2df6274b1dd2971d7bf434b272f7c70b766f367c52a49c9fdd999af44fac3ee440cb75a78a9b8dbf40ee24d7a501468ae4610e8727546f7ddb7d06eafb7a285bb86e3e5bb2ba463b778ceabdc68deac1fdc4cc07bff942a06807ed17f85da2f223bb8daa7f9cd2c1429f3a6217615b6c56d7318ce86575f653d5a17cc56d6a37ff7bb7e5b2a712f3a5ccb5ce331d58fac1c38d15c8bcc8fa75374
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109728);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/20");

  script_cve_id(
    "CVE-2018-0226",
    "CVE-2018-0234",
    "CVE-2018-0235",
    "CVE-2018-0252"
  );
  script_bugtraq_id(104080, 104081, 104124);
  script_xref(name:"CISCO-BUG-ID", value:"CSCva68116");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf73890");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg07024");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf89222");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180502-aironet-ssh");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180502-ap-ptp");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180502-wlc-mfdos");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180502-wlc-ip");

  script_name(english:"Cisco Wireless LAN Controller Multiple Vulnerabilities");
  script_summary(english:"Checks the Cisco Wireless LAN Controller (WLC) version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Wireless LAN 
Controller (WLC) is affected by one or more vulnerabilities. 
Please see the included Cisco BIDs and the Cisco Security 
Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180502-aironet-ssh
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e1aa030");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180502-ap-ptp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fe723823");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180502-wlc-mfdos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?468b6972");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180502-wlc-ip
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?24673826");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCva68116");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf73890");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg07024");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf89222");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCva68116, CSCvf73890, CSCvg07024, and CSCvf89222.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0226");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cpe:/h:cisco:wireless_lan_controller");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Port");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");
include("global_settings.inc");

product_info = cisco::get_product_info(name:"Cisco Wireless LAN Controller (WLC)");

if (product_info['model'] !~ "[^0-9]+(18|28|38|55|85)[0-9][0-9][^0-9]+" &&
    product_info['version'] != "8.5.103.0")
  audit(AUDIT_HOST_NOT, "affected");

if (product_info['model'] =~ "[^0-9]+(18)[0-9][0-9][^0-9]+")
{
  min_ver = '8.2.121.0';
}
else if (product_info['model'] =~ "[^0-9]+(28|38)[0-9][0-9][^0-9]+")
{
  min_ver = '8.2.102.0';
}
else if (product_info['model'] =~ "[^0-9]+(55|85)[0-9][0-9][^0-9]+")
{
  min_ver = '8.4.0.0';
}
else
{
  min_ver = '8.2.0.0';
}

vuln_ranges = [
  { 'min_ver' : min_ver, 'fix_ver' : '8.5.120.0' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , "CSCva68116, CSCvf73890, CSCvg07024, and CSCvf89222"
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_ranges);
