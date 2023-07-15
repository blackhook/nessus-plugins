#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108406);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2018-0147", "CVE-2018-0218");
  script_bugtraq_id(103328, 103345);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh25988");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve70616");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180307-acs2");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180307-acs1");
  script_xref(name:"IAVA", value:"2018-A-0084");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");

  script_name(english:"Cisco Secure Access Control Multiple Vulnerabilities (cisco-sa-20180307-acs1 / cisco-sa-20180307-acs2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Secure Access Control System (ACS) running on the
remote host is prior to 5.8.0.32.9 Cumulative Patch. It is, therefore, 
affected by multiple vulnerabilities.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180307-acs2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e98b9cb0");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180307-acs1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?41f35c0f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 5.8.0.32.9 Cumulative Patch or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0147");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:secure_access_control_system");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_secure_acs_version.nasl");
  script_require_keys("Host/Cisco/ACS/Version", "Host/Cisco/ACS/DisplayVersion");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/ACS/Version");
display_ver = get_kb_item_or_exit("Host/Cisco/ACS/DisplayVersion");

fix = '5.8.0.32.9';

if ( ver_compare(ver:ver, fix:fix, strict:FALSE) < 0 )
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    version  : display_ver,
    bug_id   : "CSCvh25988a",
    fix      : fix
  );
}
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Secure ACS', display_ver);
