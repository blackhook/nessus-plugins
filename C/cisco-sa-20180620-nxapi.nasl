#TRUSTED 664dfff3235ff013bcaf23fd6e1556c1e3cfd57b04ad2c99a863e7554c0831e73854a188076f2881102ab5f2ee62bcacd4799f5fcd8ecb1ab5b358c56c809d99626a235f621118f8b15c1eff3f0b772445d71da6f365244f65cd606c12c39fe15291a309a89222b908e86bfc5e8f9a6d07c47277c2ea6522fce1472c4cc3ffcda0b90dc1acd86e9e72801a3c8b8c5f697573a40617f750399d1f58f17a1f4d022fcab0e7b16b6f91e7fd0cfd03a133e77e77a961153d5e9955f44cd0f9b16da61cad5379a81e5e5856141458c5e11623193087e84b0227517ae126154721e4492db6f4bfa44e57ff1933fa3290b78b0bab787170fc4b14fc94c4d13b2aa5aeee42463c38277c629e412ee34d2c8a4fba14fab0dab347b7e315cc7910a84088a1e6d053a95a630eabe4aad6615e63d4eb1bcdf4ee225fd4d4dabe9a06fadf2a62df9d5d19985640c9f2ef218e2e43b76482e24fd9bd120a5bd7a797ed6a67a04eb459550bd4e9335de979a82a318dcd944b0631e295fc35ffb3589a5a059c9e514192c288ab725b4c0fa6501b2482b8d78c197736aa2cbb2450bf6ad8ed66e33a8c88268e91fa7df3d34523c8be73894df71bab00ba35f9eb0604e6239cdc7018fca6dd0a8ea995a8369a69efe604beb0e0fe5e8600978e88992eaae3950ed056fc17c3825770aeaa20b87badb4fdfdec636521b5ee064e7068a5db857552905f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110688);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/19");

  script_cve_id("CVE-2018-0301", "CVE-2018-0313", "CVE-2018-0330");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd45804");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02322");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02412");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve40903");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc73177");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve40911");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd47415");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve03216");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve03224");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd47415");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve03216");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve03234");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-nxos-bo");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-nxos-nxapi");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-nx-os-api-execution");

  script_name(english:"Cisco NX-OS NXAPI Multiple Vulnerabilities.");
  script_summary(english:"Checks the Cisco NX-OS Software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco NX-OS Software is
affected by one or more vulnerabilities. Please see the included Cisco
BIDs and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-nxos-bo
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4542be2");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-nxos-nxapi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ca36efb9");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-nx-os-api-execution
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1f5cb16d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd45804");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02322");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02412");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve40903");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc73177");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve40911");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd47415");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve03216");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve03224");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd47415");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve03216");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve03234");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed / recommended version referenced in Cisco Security
Advisories.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0301");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  vuln_range = [{ 'min_ver' : '7.3', 'fix_ver' : '8.1.2' }];
  bugIDs = "CSCvd45804, CSCve40903 , CSCvd47415";
}
else if ('Nexus' >< product_info['device'])
{
  if (product_info['model'] =~ '^30[0-9][0-9]')
  {
    vuln_range = [{ 'min_ver' : '0',        'fix_ver' : '7.0(3)I4(7)' },
                  { 'min_ver' : '7.0(3)I5', 'fix_ver' : '7.0(3)I7(1)' }];
    bugIDs = "CSCve02322, CSCvc73177, CSCve03216";
  }
  else if (product_info['model'] =~ '^35[0-9][0-9]')
  {
    vuln_range = [{ 'min_ver' : '6.0', 'fix_ver' : '7.0(3)I7(2)' }];
    bugIDs = "CSCve02322, CSCvc73177, CSCve03216";
  }
  else if (product_info['model'] =~ '^2[0-9][0-9][0-9]' ||
           product_info['model'] =~ '^5[56][0-9][0-9]'  ||
           product_info['model'] =~ '^6[0-9][0-9][0-9]')
  {
    vuln_range = [{ 'min_ver' : '7.3', 'fix_ver' : '7.3(3)N1(1)' }];
    bugIDs = "CSCvd45804, CSCve40911, CSCve03224";
  }
  else if (product_info['model'] =~ '^7[07][0-9][0-9]')
  {
    vuln_range = [{ 'min_ver' : '7.3', 'fix_ver' : '7.3(2)D1(1)' },
                  { 'min_ver' : '8.0', 'fix_ver' : '8.1(2)' }];
    bugIDs = "CSCvd45804, CSCve40903, CSCvd47415";
  }
  else if (product_info['model'] =~ '^9[0-4][0-9][0-9]')
  {
    vuln_range = [{ 'min_ver' : '0',        'fix_ver' : '7.0(3)I4(7)' },
                  { 'min_ver' : '7.0(3)I5', 'fix_ver' : '7.0(3)I7(1)' }];
    bugIDs = "CSCve02322, CSCvc73177, CSCve03216";
  }
  else if (product_info['model'] =~ '^9[5-9][0-9][0-9]')
  {
    vuln_range = [{ 'min_ver' : '7.0', 'fix_ver' : '7.0(3)F2(1)' }];
    bugIDs = "CSCve02412, CSCve03234";
  }
}

if (isnull(vuln_range) || isnull(bugIDs)) audit(AUDIT_HOST_NOT, 'affected');

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['nxos_nxapi'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , bugIDs
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_range);
