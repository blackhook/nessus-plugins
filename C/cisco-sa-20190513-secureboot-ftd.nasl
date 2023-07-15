#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(125341);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/27");

  script_cve_id("CVE-2019-1649");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn77248");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190513-secureboot");
  script_xref(name:"IAVA", value:"2019-A-0177");

  script_name(english:"Cisco Firepower Threat Defense (FTD) Secure Boot Hardware Tampering Vulnerability (cisco-sa-20190513-secureboot)");
  script_summary(english:"Checks the version of Cisco Firepower Threat Defense.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its version, the Cisco Firepower Threat Defense (FTD) software installed on the remote host is affected by
a vulnerability in the logic that handles access control to one of the hardware components in Cisco's proprietary Secure
Boot implementation could allow an authenticated, local attacker to write a modified firmware image to the component.
This vulnerability affects multiple Cisco products that support hardware-based Secure Boot functionality. The
vulnerability is due to an improper check on the area of code that manages on-premise updates to a Field Programmable
Gate Array (FPGA) part of the Secure Boot hardware implementation. An attacker with elevated privileges and access to
the underlying operating system that is running on the affected device could exploit this vulnerability by writing a
modified firmware image to the FPGA. A successful exploit could either cause the device to become unusable (and require
a hardware replacement) or allow tampering with the Secure Boot verification process, which under some circumstances may
allow the attacker to install and boot a malicious software image.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190513-secureboot
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e13bd4a7");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn77248");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvn77248");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1649");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:cisco:firepower");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CISCO");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl", "cisco_asa_firepower_version.nasl", "cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "Settings/ParanoidReport");
  exit(0);
}

include('vcf.inc');
include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_info = vcf::get_app_info(app:'Cisco Firepower Threat Defense');
product_info = make_array('model' , app_info['Model'], 'version' , app_info['version'], 'name', 'Cisco Firepower Threat Defense');

vuln_ranges = [
  {'min_ver' : '6.4',  'fix_ver' : '6.4.0.1'},
  {'min_ver' : '6.3',  'fix_ver' : '6.3.0.3'},
  {'min_ver' : '6.2.3', 'fix_ver' : '6.2.3.12'},
  {'min_ver' : '0.0',  'fix_ver' : '6.2.2.5'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvn77248'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
