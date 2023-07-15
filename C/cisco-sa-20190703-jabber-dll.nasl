#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(126642);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/05");

  script_cve_id("CVE-2019-1855");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo55994");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo63008");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190703-jabber-dll");
  script_xref(name:"IAVB", value:"2019-B-0055-S");

  script_name(english:"Cisco Jabber for Windows DLL Preloading Vulnerability (cisco-sa-20190703-jabber-dll)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Jabber for Windows is affected by a vulnerability in the loading
mechanism of specific dynamic link libraries due to insufficient validation of the resources loaded by the application
at run time. An authenticated, local attacker can exploit this to perform a DLL preloading attack by crafting a
malicious DLL file and placing it in a specific location on the targeted system. The malicious DLL file would execute
when the Jabber application launches. A successful exploit could allow the attacker to execute arbitrary code on the
target machine with the privileges of another user's account.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190703-jabber-dll
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c52a87e");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo55994
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d2debab");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo63008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f1057302");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvo55994, CSCvo63008");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1855");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:jabber");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_jabber_client_installed.nbin");
  script_require_keys("installed_sw/Cisco Jabber for Windows");

  exit(0);
}

include('audit.inc');
include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Cisco Jabber for Windows', win_local:TRUE);

constraints = [
  { 'fixed_version' : '12.6.2', 'fixed_display' : '12.6(2)'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

