#TRUSTED 5f2b66a85fffcf3fb8941007d356ec1b2b1ac9caad0283747962dd662cf83ae8b57cd00f63fb2d4766024bb29b74b95456f044cdf29bc3e5cad40b3f33e7fbf408b566ace815f879521406c166543415d3783184687b636ee5d7e689ffdaa01c120bc153f1299bcbf3b482bb561b65414ba70c4bdf8f03a87f22d8eb1300edbb5a483dfbd25b430fae27eb194246cf0eec4958f115224a0df1e02a8a11cdf3504d95f3e091c652bc74814146bdfca1b9eea3e3cda052b64a1be0f2599ca667219d63e89053dcacf72446d3b617e59da5a35b4b9bca2cb506f07eb428c7b5ce5e7f1c470b0ca7cb53a3dfab915f77e18109b1f9ebce29eaed3b3fc02d9b69c12700abfac4e97e21673751dbbc3bc0f8edc77a69a607aa3596f0e2d14d32417d841683867ef2cebc13ce84ff13bb3ac334beae4bdb1a616cbb877057eecaf4618c2656ec7d6f57fbf44dda51412de80b83f54f0ae36ae44557f128ead8e217af285886a5dfc78ba2b13b66660cdb51160713eae6b8e51ba7a59a70b32ade56a60bdbac4a922e151a7eb9c6fab5096064eb3e1b2cb409caba8e1e924d8ccb54b0fc6cda9bf1e6431618aeda16fadf4e91e0e739720234889bede708ee3c060991a510bc6e1a446c8570b238af289027ead3e3b864674d8dfad4648ecfdf495dbd78a6c03a5494c85d3a067290bd4a2aa0e5811ad630d04a6437716ec260dbaa73db
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126073);
  script_version("1.5");
  script_cvs_date("Date: 2019/12/13");

  script_cve_id("CVE-2019-1606");
  script_bugtraq_id(107345);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh85760");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190306-nxos-cmdinj-1606");
  script_xref(name:"IAVA", value:"2019-A-0159");

  script_name(english:"Cisco NX-OS Software CLI Command Injection Vulnerability (CVE-2019-1606)");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a vulnerability in the CLI of Cisco NX-OS
Software could allow an authenticated, local attacker to execute arbitrary commands on the underlying operating system
of an affected device.The vulnerability is due to insufficient validation of arguments passed to certain CLI commands.
An attacker could exploit this vulnerability by including malicious input as the argument of an affected command. A
successful exploit could allow the attacker to execute arbitrary commands on the underlying operating system with
elevated privileges. An attacker would need valid user credentials to exploit this vulnerability.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190306-nxos-cmdinj-1606
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?25095108");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-70757");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh85760");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvh85760");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1606");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if (product_info.device != 'Nexus' || product_info.model !~ '^(3[05]|90)[0-9][0-9]')
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '7.0(3)I7(3)',
  '7.0(3)I7(2)',
  '7.0(3)I7(1)'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvh85760'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list, switch_only:TRUE);
