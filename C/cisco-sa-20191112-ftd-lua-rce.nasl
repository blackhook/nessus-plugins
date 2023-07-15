#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131229);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/15");

  script_cve_id("CVE-2019-15992");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96680");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191112-asa-ftd-lua-rce");
  script_xref(name:"IAVA", value:"2019-A-0425-S");

  script_name(english:"Cisco Firepower Threat Defense RCE (cisco-sa-20191112-asa-ftd-lua-rce)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A remote code execution vulnerability exists in the Lua interpreter of Cisco Firepower Threat Defense (FTD) software
due to insufficient restrictions on the allowed Lua function calls within the context of user-supplied Lua scripts. An
authenticated, remote attacker can exploit this to bypass authentication and execute arbitrary commands with root
privileges on the underlying Linux operating system of an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191112-asa-ftd-lua-rce
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0e82478b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr96680");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr96680.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15992");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl", "cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('misc_func.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');
# Check is on a VDB build number, not version of product
vdb_build = product_info['VDB Version'];

report = '';
fixed_version = '329';
if (ver_compare(ver:vdb_build, fix:fixed_version, strict:FALSE) < 0)
{
  report += '\n  Installed VDB build : ' + vdb_build +
            '\n  Fixed VDB build     : ' + fixed_version +
            '\n  Cisco bug ID        : CSCvr96680' +
            '\n';
}

if (empty(report))
  audit(AUDIT_HOST_NOT, 'affected');

security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
