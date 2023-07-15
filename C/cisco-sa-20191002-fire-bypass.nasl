#
# (C) Tenable Network Security, Inc.
#
include('compat.inc');

if (description)
{
  script_id(130457);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2019-12701");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp92361");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191002-fire-bypass");
  script_xref(name:"IAVA", value:"2019-A-0372-S");

  script_name(english:"Cisco Firepower Management Center Software File and Malware Policy Bypass Vulnerability (cisco-sa-20191002-fire-bypass)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported VDB version, Cisco Firepower Management Center is affected by a file and malware 
inspection policy bypass vulnerability, in its VDB component, due to insufficient validation of incoming traffic. An 
unauthenticated, remote attacker could exploit this, by sending crafted HTTP requests, to bypass inspection policies 
and send malicious traffic through the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191002-fire-bypass
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d3ca1c5e");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp92361
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ed1b44e7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID 
  CSCvp92361");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12701");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_management_center");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_firepower_version.nasl");
  script_require_keys("Host/Cisco/firepower_mc/vdb_build");

  exit(0);
}

include('audit.inc');
include('misc_func.inc');

# Check is on a VDB build number, not version of product
vdb_build = get_kb_item_or_exit('Host/Cisco/firepower_mc/vdb_build');

report = '';
fixed_version = '327';
if (ver_compare(ver:vdb_build, fix:fixed_version, strict:FALSE) < 0)
{
  report += '\n  Installed VDB build : ' + vdb_build +
            '\n  Fixed VDB build     : ' + fixed_version +
            '\n';
}

if (empty(report))
  audit(AUDIT_HOST_NOT, 'affected');

security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);
