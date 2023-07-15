#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(148451);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/15");

  script_cve_id("CVE-2020-3432");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt78191");
  script_xref(name:"CISCO-SA", value:"cisco-sa-anyconnect-mac-dos-36s2y3Lv");

  script_name(english:"Cisco AnyConnect Secure Mobility Client for Mac OS File Corruption (cisco-sa-anyconnect-mac-dos-36s2y3Lv)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco AnyConnect Secure Mobility Client is affected by a file corruption
vulnerability. The vulnerability is due to the incorrect handling of directory paths. An authenticated, attacker
could exploit this vulnerability by creating a symbolic link (symlink) to a target file on a specific path. A
successful exploit could allow the attacker to corrupt the contents of the file. If the file is a critical systems
file, the exploit could lead to a denial of service condition. To exploit this vulnerability, the attacker would
need to have valid credentials on the system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-anyconnect-mac-dos-36s2y3Lv
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c25c418f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt78191");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt78191");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3432");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(59);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_cisco_anyconnect_installed.nasl");
  script_require_keys("installed_sw/Cisco AnyConnect Secure Mobility Client", "Host/MacOSX/Version");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('Host/MacOSX/Version');

app_info = vcf::get_app_info(app:'Cisco AnyConnect Secure Mobility Client');

constraints = [{ 'fixed_version' : '4.9.00086' }];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);
