#TRUSTED 5a6230e8c26361f0c9d5d595f1db3d55674a00bbc7e4e5d6f6b398b972f92f6fd81fbd077676604f0afe823f6dd8da6ad99cc6fa6d17fbe7a9d39464e532c7a585ff3d7deac258f9a103821b9de153ddf22ee898bfacba48b2ce1510f9277f727e78b7e9502e8f70d1bc07490a90a5434b41d28876dcb22c7e90541f235934461d46c2dd725abb87cdf177ad294de4c271b0db8d7e53351317ca89fc08d7c6f54979875a722e88f6f9e5378e9203a1aedd147f1117212c92f88853ea7854678ad418e21b048b7dd94a98cec2815e5995077248862b2291178b6153601bc42a4aa9ed8813135d192ab03cc3ee4b7071cac884ff452c78e16122b3f589f6d97c86fe961072d04db180025df566c75defe29e05a3eec96749b4f93d258b34de5c7e7b162fa915000174126b91ec75a689676b8eafc84deb273f34fd539bd57eee3a751c7b331ddda853125753e0d3bdce9dc1edd352cd6f6c2789374110abe3f20cdf2ee8d3954be134688bf0c2cc196812e2fc62cb1cefbc0fc76564168a5f1ecdd705340632084ab0fac1956343be7e3ca4ca8565773170d3019ecbeab86ca77f77cd203992c98a99ecf3ffbbe8f4f8f4bfcfa0ac8fba0b4446979dba7ba85e5c384fc0610fa7b51d721bd7b54809f4fd2a93a0ff71725d1e48aeca192069b944841b5c94ef76b7f9d6736e567f5affb097201c73d4f44d333f56035935137991
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126100);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2019-1712");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg43676");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190417-iosxr-pim-dos");

  script_name(english:"Cisco IOS XR Software Protocol Independent Multicast Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XR Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR Software is
affected by a vulnerability in the Protocol Independent Multicast
(PIM) feature of Cisco IOS XR Software.  This could allow an 
unauthenticated, remote attacker to cause the PIM process to 
restart, resulting in a denial of service condition on an affected 
device.The vulnerability is due to the incorrect processing of 
crafted AutoRP packets. An attacker could exploit this vulnerability 
by sending crafted packets to port UDP 496 on a reachable IP address 
on the device. A successful exploit could allow the attacker to cause
 the PIM process to restart. (CVE-2019-1712)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190417-iosxr-pim-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?47555f76");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg43676");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvg43676");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1712");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XR");
if (report_paranoia < 2) audit(AUDIT_PARANOID);

vuln_ranges = [
  {'min_ver' : '4.0.0',  'fix_ver' : '6.2.3'},
  {'min_ver' : '6.3.0',  'fix_ver' : '6.3.2', 'fix_display': '6.3.2 / 6.4.0'},
  {'min_ver' : '6.5.0',  'fix_ver' : '6.5.1'},
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
'port'     , product_info['port'],
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvg43676'
);

cisco::check_and_report(
    product_info:product_info,
    workarounds:workarounds,
    workaround_params:workaround_params,
    reporting:reporting,
    vuln_ranges:vuln_ranges
  );
