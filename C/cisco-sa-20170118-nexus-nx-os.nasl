#TRUSTED 7f587e0a26cc26704e097412f606a8d430b34b0126d55cd02bad0ffa90ae75367b4547ef75eb468f25d098032f7af92002bad3abeb2cff7fc2e073bd0d6fb37dbb3f1719d369f7ee30c44be6290a1170a1938903496f5a9e83aafc215682f912165e282cfc1c5f07090eadfe0d7c3a7c12b66d56007ff2dabfa4b3dbb393f6735e0a092ec76df788f9fae1d362b024feff3267bd2590df7273cdbecc87731e0085304a27289c76ae6b42237888e1553091fd6f2e78584025956cf558ad2dd9e7878668fa1393770980ca30cdd42387fa6027d984ce9d94734904f3f277c3ebd37f965410e056556289d92226e431bae0b5087323eaa5aa96a20389f1172f896673bb31f73125e67c1c3e24757128287ccd7237f53b1772bf228d9082381308a698929a23ccbd3960897256a88958cd059cb5f2a6517a74bfdf4b5807d9b72adc37b1e41ffca2d4cc97158aab4de4fae33ebae344769bfacc2276831c9f52d698998d9f7b9850f52fea11e81cba1367a68f434f0cd646e43795bc6697fa6cadc8db369499705305ccf1126fab4cdba6fbe05fa7bf567f4b42f051fa09e3b1927b2375a7ab68a86279bb29ee30d3c54a8346c136db887a6cc3f38fc892d579843626b6e04f9340cad4fe5683fe1823b8de3c809988a784e2f8044a83560eb3a003d2580a9729da3181339044f1b9ba714980e27cf155e6035bcd23d6d620b11583
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102995);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/24");

  script_cve_id("CVE-2017-3804");
  script_bugtraq_id(95638);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc45002");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170118-nexus");

  script_name(english:"Cisco NX-OS IS-IS Packet Processing Denial of Service Vulnerability");
  script_summary(english:"Checks the Cisco NX-OS Software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco NX-OS Software is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170118-nexus
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?63c3627f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc45002");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvc45002.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3804");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:nexus_1000v");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

device = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");
version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");

# Only models 5000, 6000, and 7000 are affected as well as specific MDS models
if (
  ('Nexus' >< device && model !~ "^[567][0-9][0-9][0-9]([^0-9]|$)$") ||
  (('MDS' >< device) && (model != "9710" &&
  model != "9124" &&
  model != "9148S" &&
  model != "9250i" &&
  model != "9222i" &&
  model != "9509" &&
  model != "9134" &&
  model != "9506" &&
  model != "9396S" &&
  model != "9148" &&
  model != "9513" &&
  model != "9706" &&
  model != "9718"))
  )audit(AUDIT_HOST_NOT, "an affected device and/or model");

product_info = cisco::get_product_info(name:"Cisco NX-OS Software");

version_list = make_list(
  "6.2(10)",
  "7.1(3)N1(2.1)",
  "7.1(3)N1(3.12)",
  "7.1(4)N1(0.1)",
  "7.2(0)D1(1)",
  "7.3(0)D1(1)",
  "7.3(0)N1(0)",
  "7.3(1)D1(1)",
  "7.3(1)N1(1)",
  "7.3(2)N1(0.296)",
  "8.0(1)S2"
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvc45002",
  'fix'      , "See advisory"
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
