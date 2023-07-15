#TRUSTED 61d935c9960020b6882c5cbe493afb0248c922650bfd5130ea00d308cfbd657a41340c31e92ed915338207f3ebc6a471302c5e799791a23b78925d9a66a44e9e78307b2499f58e8e5d96d443aea786874046668279235bb1e84360e8f149a9409d1f3b1f66aeae6178e91ddd55f7b28ae28052954b0f63e451b92ac102513dc083a5cee101581c96db1d48ececc4ad8cb4e49bf9b5c1e3a548a154a57dcda5cea418062eb0236eed9f08b801801b6581754548da41fcf76a191be769101eef2d46ba72aeef6d74d9d5deb77458e18e73da55d5591b2c516392783f3f5124b0cbc0e3fd665b28ddea51bac9427e374ca443bcf3562fb99d3cdedb4e9b7ddafe3ba87d70ac1a56b49d8717203472c84c4758755e8e3a9491056eb8df0b5b3a8c9cfa684b67c4bcf5f2600c10d069a459b55cccde4d1d3289106f7cbeb2459c0e1bafd8bb1bc25f630cbeff2a28d4a11ab86c61d7e721e9d23e9c1af2310cbbbc243b2f4622599c5d96d42d7520c44fa4d0380a309cb208da38703809006ffba8737886744a0532cc34a5f20b0540fd90a7d70b8595f278e6d088be918ae764273efbbe62e752414bbce0b32cdf57add346fdce867faf7423db5d768dbfe3a6dd9b6e5e8928bc85bd2687e34b9217d9d411efe5a394e0fcd1a482a7796c3d4a1c5df03a3e6f602987cb9d9762c84f3d0ae680502c38bdffb23190c08643e5b2f42e
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159712);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/03");

  script_cve_id("CVE-2022-20676");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy35833");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-priv-esc-grbtubU");

  script_name(english:"Cisco IOS XE Software Tool Command Language Privilege Escalation (cisco-sa-iosxe-priv-esc-grbtubU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in the Tool Command Language (Tcl) interpreter of Cisco IOS XE Software could allow an
    authenticated, local attacker to escalate from privilege level 15 to root-level privileges. This
    vulnerability is due to insufficient input validation of data that is passed into the Tcl interpreter. An
    attacker could exploit this vulnerability by loading malicious Tcl code on an affected device. A
    successful exploit could allow the attacker to execute arbitrary commands as root. By default, Tcl shell
    access requires privilege level 15. (CVE-2022-20676)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-priv-esc-grbtubU
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b8aa4a51");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74561");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy35833");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy35833");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20676");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(250);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var version_list=make_list(
  '16.12.1z2',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v',
  '17.2.2',
  '17.2.3',
  '17.3.1',
  '17.3.1a',
  '17.3.1w',
  '17.3.1x',
  '17.3.1z',
  '17.3.2',
  '17.3.2a',
  '17.3.3',
  '17.3.3a',
  '17.3.4',
  '17.3.4a',
  '17.3.4b',
  '17.3.4c',
  '17.4.1',
  '17.4.1a',
  '17.4.1b',
  '17.4.1c',
  '17.4.2',
  '17.4.2a',
  '17.5.1',
  '17.5.1a'
);

var reporting = make_array(
  'port'          , product_info['port'],
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvy35833',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
