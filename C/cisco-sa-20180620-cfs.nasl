#TRUSTED 0811d53856ed168d1ab1172a4386ddb1f52949ad3a482a7a4105628a94af24ee8f19a255410e52058e59d68682c39cd03a4ef03fa4a1b355c7594b41745ea8c51f0c679489b06c0aae1a8e97cea6651504d4ed0eb6e2feba7f91cc631d8c283e54b5c7c9337b712053d9d6ee215ada9b40533c0f4b7d7c8a7105345dde2e0fc801ce24a435fe14dbd075916b5e192309b1875bc328e8778936c4ef5f7f7cc1d6d8a818dacc5673151a9e682b919b3357426c39adb206fde63ac3c6e31a118b62e3193aa96daea818e5f9faaf2cd1ee7731fc7dcba3d4cbb2d0d3aabb0e799dbd49dd65e78d9bd7e296c5051d87afb14e38725b9de4d75e69fd2a86d31e04e349ee37124d9d71baf05012a35d598578da01c82f765778898b85c35b18da9ea0416182e9a39cadfbfbe6685fa07d3d35b0c013e02b138ce085131b9aab4ad6d96bc3af32f8b27dac2a3e22ca683b4e0ab6109c0060f9a506647958b27d0a656ed2143a1b5b40334128a7247290ae05da5d27731aca74041a31e4e9baa70e87dc1598f24807464788865d50ee3d280f6e71f61ce1994c4c8493b57f006e45dc20e6a16540c8329eca37c83dc9d14297f54affc053484d7da72eb1cdee47f3cae7acf5e19c21f74d2474c6b30f9aaaac66ddd4a5409faa12c53c125a5777d83906a01a24fb39f08182edfe97044651967d679ab0b902a302124386ddf43a45ecb198
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110687);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/27");

  script_cve_id(
    "CVE-2018-0304",
    "CVE-2018-0305",
    "CVE-2018-0308",
    "CVE-2018-0310",
    "CVE-2018-0311",
    "CVE-2018-0312",
    "CVE-2018-0314"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd69943");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd69951");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd69954");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd69957");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd69960");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd69962");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd69966");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02429");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02433");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02435");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02445");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02459");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02461");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02463");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02474");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02785");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02787");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02804");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02808");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02810");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02812");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02819");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02822");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02831");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve04859");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve41530");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve41536");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve41537");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve41538");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve41541");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve41557");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve41559");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve41590");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve41593");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve41601");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-fxnxos-fab-ace");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-fxnxos-ace");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-fx-os-fabric-execution");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-fx-os-cli-execution");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-nx-os-fabric-services-dos");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-nx-os-fabric-dos");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-fx-os-fabric-dos");

  script_name(english:"Cisco NX-OS Cisco Fabric Services Multiple Vulnerabilities.");
  script_summary(english:"Checks the Cisco NX-OS Software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco NX-OS Software is
affected by one or more vulnerabilities. Please see the included Cisco
BIDs and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-fxnxos-fab-ace
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6219c29b");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-fxnxos-ace
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?267dc032");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-fx-os-fabric-execution
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?217b85b2");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-fx-os-cli-execution
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0884367f");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-nx-os-fabric-services-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7a5a1307");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-nx-os-fabric-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f589839d");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-fx-os-fabric-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?33153cf4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd69943");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd69951");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd69954");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd69957");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd69960");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd69962");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd69966");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02429");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02433");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02435");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02445");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02459");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02461");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02463");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02474");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02785");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02787");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02804");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02808");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02810");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02812");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02819");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02822");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02831");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve04859");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve41530");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve41536");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve41537");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve41538");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve41541");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve41557");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve41559");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve41590");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve41593");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve41601");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed / recommended version referenced in Cisco Security
Advisories.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0304");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco NX-OS Software");

vunl_range = make_array();
bugIDs = NULL;

if (('MDS' >< product_info['device']) && (product_info['model'] =~ '^9[0-9][0-9][0-9]'))
{
  vuln_range = [{ 'min_ver' : '5.2', 'fix_ver' : '6.2(21)' },
                { 'min_ver' : '7.3', 'fix_ver' : '8.1(1a)' }];
  bugIDs = "CSCvd69954, CSCvd69951, CSCvd69943, CSCvd69962, CSCvd69960, CSCvd69957, CSCvd69966";
}
else if ('Nexus' >< product_info['device'])
{
  if (product_info['model'] =~ '^30[0-9][0-9]')
  {
    vuln_range = [{ 'min_ver' : '0',        'fix_ver' : '7.0(3)I4(8)' },
                  { 'min_ver' : '7.0(3)I5', 'fix_ver' : '7.0(3)I7(4)' }];
    bugIDs = "CSCve02785, CSCve02459, CSCve02429, CSCve02810, CSCve41537, CSCve41536, CSCve41590";
  }
  else if (product_info['model'] =~ '^35[0-9][0-9]')
  {
    vuln_range = [{ 'min_ver' : '6.0', 'fix_ver' : '7.0(3)I7(4)' }];
    bugIDs = "CSCve02785, CSCve02459, CSCve02429, CSCve02808, CSCve41530, CSCve41536, CSCve41590";
  }
  else if (product_info['model'] =~ '^2[0-9][0-9][0-9]' ||
           product_info['model'] =~ '^5[56][0-9][0-9]'  ||
           product_info['model'] =~ '^6[0-9][0-9][0-9]')
  {
    vuln_range = [{ 'min_ver' : '0', 'fix_ver' : '7.3(3)N1(1)' }];
    bugIDs = "CSCve02463, CSCve02435, CSCve02822, CSCve02463";
  }
  else if (product_info['model'] =~ '^7[07][0-9][0-9]')
  {
    vuln_range = [{ 'min_ver' : '6.2', 'fix_ver' : '6.2(20)' },
                  { 'min_ver' : '7.2', 'fix_ver' : '7.3(2)D1(1)' },
                  { 'min_ver' : '8.0', 'fix_ver' : '8.1(2)' }];
    bugIDs = "CSCvd69954, CSCvd69951, CSCvd69943, CSCvd69962, CSCvd69960, CSCvd69957, CSCvd69966";
  }
  else if (product_info['model'] =~ '^9[0-4][0-9][0-9]')
  {
    vuln_range = [{ 'min_ver' : '0',        'fix_ver' : '7.0(3)I4(8)' },
                  { 'min_ver' : '7.0(3)I5', 'fix_ver' : '7.0(3)I7(4)' }];
    bugIDs = "CSCve02785, CSCve02459, CSCve02429, CSCve02812, CSCve41537, CSCve41536, CSCve41590";
  }
  else if (product_info['model'] =~ '^9[5-9][0-9][0-9]')
  {
    vuln_range = [{ 'min_ver' : '7.0', 'fix_ver' : '7.0(3)F3(1)' }];
    bugIDs = "CSCve02804, CSCve02474, CSCve02445, CSCve02831, CSCve41557, CSCve41559, CSCve41601";
  }
}

if (isnull(vuln_range) || isnull(bugIDs)) audit(AUDIT_HOST_NOT, 'affected');

workarounds = make_list(CISCO_WORKAROUNDS['cfs_enabled']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , bugIDs
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_range);
