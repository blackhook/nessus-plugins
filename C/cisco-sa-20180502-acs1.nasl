#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110399);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-0253");
  script_bugtraq_id(104075);
  script_xref(name:"CISCO-BUG-ID", value:"CSCve69037");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180502-acs1");

  script_name(english:"Cisco Secure Access Control (cisco-sa-20180502-acs1)");
  script_summary(english:"Checks the ACS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Secure Access Control System (ACS) running on the
remote host is prior to 5.8.0.32.7 Cumulative Patch. It is, therefore, 
affected by a flaw in the ACS Report component that is triggered when
 handling specially crafted Action Message Format (AMF) messages. 
This may allow a remote attacker to potentially execute arbitrary 
code.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180502-acs1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a07297b");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve69037
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb65122e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 5.8.0.32.7 Cumulative Patch or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:secure_access_control_system");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_secure_acs_version.nasl");
  script_require_keys("Host/Cisco/ACS/Version", "Host/Cisco/ACS/DisplayVersion");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/ACS/Version");
display_ver = get_kb_item_or_exit("Host/Cisco/ACS/DisplayVersion");

fix = '5.8.0.32.7';

if ( ver_compare(ver:ver, fix:fix, strict:FALSE) < 0 )
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    version  : display_ver,
    bug_id   : "CSCve69037",
    fix      : fix
  );
}
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Secure ACS', display_ver);
