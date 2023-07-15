#TRUSTED 717c60e2f73b6618a4917de9e7a7af7a29eff46fdcd716f03cded754d013dbfad008f95cb5bddde65784995da8a8f9ea4c3b7e25dda680b2a2081cc6936921844c0cb72109f9a2bc42853f3280ed0c8361e46e97aeff588e39803361b1c02cd6cd6168f389e01862cbd2394a6e429da6bd56825844f8b94adfe7a4a2f75e7817bb1f00f991d9ba43fb9d98ecc2d4f61ab87b8d1c0efdd92ebd7d1a36dd864cbc3b0ed891a65668f9abf2875f58ddd65edbdffb4daf06c34690d784b2375b82a4cce5e99586f31469d4cb4fe2ef6227726e026df8ba7ca0b4130149c85af82488b2156a7f2237f30327ac543395b7a146af6599c44cbbda33fae2268f074127c8e15200d3cddd1305444dcd549b37a7953828e5225c203674c1834e9bd400196d4c9d630acd707824060c4d04b36ee750044ff5ee076b0695503e854c21a2f2fdc6cb2a9b88205886e7b5e2777c4e5be1abd991389296fa11a286533ddf10e941ec17a56ab926ad136ef6dc4dfb1274f3a8a9b6ef283e7bca3e7fed7d17943bee31dcb3dbf53d4b6b4c0ef648cce5b72a0c5bf70cda55c9f694673ebc765fe5ff13f09a7d8fbdcbf5bfa455bbedcf225f09301c1b6b38adfcb72bc7370489e039848eecbb1dda9005bfa7c3efb90163907cf6ba2304fe455c5809754c38df48d3f2860102f9951174fc69bed8c095cf3717b652e57b81c57f7da5d57bbfffb8d8
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123794);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/22");

  script_cve_id("CVE-2019-1738", "CVE-2019-1739", "CVE-2019-1740");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb51688");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-nbar");
  script_xref(name:"IAVA", value:"2019-A-0097-S");

  script_name(english:"Cisco IOS XE Software Network-Based Application Recognition Denial of Service Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is
affected by following multiple vulnerabilities

  - Multiple vulnerabilities in the Network-Based
    Application Recognition (NBAR) feature of Cisco IOS
    Software and Cisco IOS XE Software could allow an
    unauthenticated, remote attacker to cause an affected
    device to reload.These vulnerabilities are due to a
    parsing issue on DNS packets. An attacker could exploit
    these vulnerabilities by sending crafted DNS packets
    through routers that are running an affected version and
    have NBAR enabled. A successful exploit could allow the
    attacker to cause the affected device to reload,
    resulting in a denial of service (DoS) condition.
    (CVE-2019-1738, CVE-2019-1739, CVE-2019-1740)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-nbar
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b838dda");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb51688");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb51688");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb51688");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs
CSCvb51688, CSCvb51688, CSCvb51688");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1740");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.2.0JA',
  '3.18.4S',
  '3.18.3S',
  '3.18.2aSP',
  '3.18.2SP',
  '3.18.2S',
  '3.18.1iSP',
  '3.18.1hSP',
  '3.18.1gSP',
  '3.18.1cSP',
  '3.18.1bSP',
  '3.18.1aSP',
  '3.18.1SP',
  '3.18.1S',
  '3.18.0aS',
  '3.18.0SP',
  '3.18.0S',
  '3.17.4S',
  '3.17.3S',
  '3.17.2S ',
  '3.17.1aS',
  '3.17.1S',
  '3.17.0S',
  '3.16.5aS',
  '3.16.5S',
  '3.16.4gS',
  '3.16.4eS',
  '3.16.4dS',
  '3.16.4cS',
  '3.16.4bS',
  '3.16.4aS',
  '3.16.4S',
  '3.16.3aS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.2aS',
  '3.16.2S',
  '3.16.1aS',
  '3.16.1S',
  '3.16.0cS',
  '3.16.0bS',
  '3.16.0aS',
  '3.16.0S',
  '16.5.1b',
  '16.5.1a',
  '16.5.1',
  '16.4.3',
  '16.4.2',
  '16.4.1',
  '16.3.4',
  '16.3.3',
  '16.3.2',
  '16.3.1a',
  '16.3.1',
  '16.2.2',
  '16.2.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['nbar']);
workaround_params = make_list();


reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvb51688, CSCvb51688 and CSCvb51688',
  'cmds'     , make_list("show ip nbar control-plane | include NBAR state")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
