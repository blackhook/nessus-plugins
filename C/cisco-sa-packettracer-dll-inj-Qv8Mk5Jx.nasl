#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(152529);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/17");

  script_cve_id("CVE-2021-1593");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx88162");
  script_xref(name:"CISCO-SA", value:"cisco-sa-packettracer-dll-inj-Qv8Mk5Jx");
  script_xref(name:"IAVA", value:"2021-A-0364");

  script_name(english:"Cisco Packet Tracer for Windows DLL Injection (cisco-sa-packettracer-dll-inj-Qv8Mk5Jx)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Packet Tracer for Windows is affected by a DLL Injection vulnerability.
An authenticated, local attacker could exploit this, by inserting a configuration file in a specific path on the system, 
to cause a malicious DLL file to be loaded. Successful exploitation could lead to arbitrary code execution.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-packettracer-dll-inj-Qv8Mk5Jx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?03b24375");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx88162");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Packet Tracer version 8.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1593");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(427);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:packet_tracer");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_packet_tracer_installed_win.nbin");
  script_require_keys("installed_sw/Cisco Packet Tracer", "SMB/Registry/Enumerated");

  exit(0);
}
include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Cisco Packet Tracer');

var constraints = [
  {'min_version': '7.3.1', 'fixed_version': '7.3.2', 'fixed_display':'8.0.1'},
  {'min_version': '8.0.0', 'fixed_version': '8.0.1'}
];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING
);