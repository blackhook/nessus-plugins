#TRUSTED 9d0fd41ec2e8c62a775d984e7c2d41817cf9078bcdeb638317bf7ec807e58d4c705830e92c51fb6b8720b2327a992952b972ce93efd9e30a432d31b57a992185b56574e2f7eb54ee1e1712f7848209e3c91bd26edbd1394839e527678e1a806a3896f749fd15bf47ddb1f29c7a951a840e3da844a43f89438011a851843d79b53a32906585964f4bd6691e522d1f70e528b08a9c1a6a7ee6e097f120b7ef937fa091a17748aaadba8345dfcd3a3ed8074ebd47e40ae9f54db05682475556b3c09ee48a5a7a3a5b53991626fa27fe3f8470584e6ccf16b25f524a0283e60a815a62ccfc29a218e25020060957d3ced512e7426688ee7b1f885b8f5a6a43e90b2886fea271434d1626ab43294456eb81b374c8b8a696f9e8837b21db2ccdcb18bb8ba210d2604d90d41850cd44b3a17e392d3af3f2f2e2d07fd0c1280148cea3f8abd60dd3a5be92270df244500f41c404f51607278c17051f66e828cdb3b80949134f633dcfab213d1dd67a1d006be292705dbb57a14e94c439ab5ca87491a77dd9721671f87b989322ba4b5fe8fb972c564a58595668017434d734971e8d7909ab0805c23ad0795f67cc4589ad10e5581b0709385240e84ea4c5e8c56c78450890ef7b4e181bdd1409713f8e97254ea3ba5181ecf6f095307a81e0354fbb3d91e3d4bfda6288022772078b63f89151b8382a51912324e964ee0c4f67333eecfc
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104127);
  script_version("1.7");
  script_cvs_date("Date: 2019/12/20");

  script_cve_id("CVE-2017-12301");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb86832");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd86474");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd86479");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd86484");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd86490");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve97102");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf12757");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf12804");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf12815");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf15198");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20171018-ppe");

  script_name(english:"Cisco NX-OS Software Python Parser Escape Vulnerability");
  script_summary(english:"Checks the Cisco NX-OS Software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco NX-OS Software is
affected by one or more vulnerabilities. Please see the included Cisco
BIDs and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171018-ppe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f51931d1");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb86832");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd86474");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd86479");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd86484");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd86490");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve97102");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf12757");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf12804");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf12815");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf15198");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Security
Advisory cisco-sa-20171018-ppe.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12301");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

device = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");

# not affected if not MDS or Nexus
if ('MDS' >!< device && 'Nexus' >!< device)
  audit(AUDIT_HOST_NOT, "an affected device and/or model");

# Only models 2000, 3000, 5000, 6000, 7000, 9000 (handled below)
# and 3500, 5500, 5600, 7700, 9500 are affected

# Affected:        Nexus 9000 Series Switches - Standalone, NX-OS mode
# Not Affected:    Nexus 9000 Series Fabric Switches - ACI mode

# We do not have a 9000 series (fabric and non-fabric), nor do we
# know the banner. For now we are only checking the 9000 series if
# we are in paranoid mode.

# the paranoid series checks are 2000, 2000, 5000, 6000, 7000, 9000
# non-paranoid series checks are 2000, 3000, 5000, 6000, 7000

if (report_paranoia >= 2)
{
  if ('Nexus' >< device &&
    model !~ "^[235679][0-9][0-9][0-9]([^0-9]|$)$" &&
    model !~ "^(35|55|77|95)[0-9][0-9]([^0-9]|$)$"
  )
    audit(AUDIT_HOST_NOT, "an affected device and/or model");
}
else
{
  if ('Nexus' >< device &&
    model !~ "^[23567][0-9][0-9][0-9]([^0-9]|$)$" &&
    model !~ "^(35|55|77|95)[0-9][0-9]([^0-9]|$)$"
  )
    audit(AUDIT_HOST_NOT, "an affected device and/or model");
}

product_info = cisco::get_product_info(name:"Cisco NX-OS Software");

version_list = make_list(
  "6.0(2)A8(3)",
  "6.0(2)A8(6.213)",
  "7.0(0)HSK(0.357)",
  "7.0(3)I4(6)",
  "7.0(7)N1(1)",
  "7.3(2)D1(0.21)",
  "8.0(0.74)",
  "8.0(1)",
  "8.1(0)BD(0.20)",
  "8.1(0.2)S0",
  "8.1(0.70)S0"
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvb86832, CSCvd86474, CSCvd86479, CSCvd86484, CSCvd86490, CSCve97102, CSCvf12757, CSCvf12804, CSCvf12815, CSCvf15198"
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
