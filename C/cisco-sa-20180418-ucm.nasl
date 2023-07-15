#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109402);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-0266");
  script_bugtraq_id(103933);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf20218");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180418-ucm");
  script_xref(name:"IAVA", value:"2018-A-0138-S");

  script_name(english:"Cisco Unified Communication Manager HTTP Interface Information Disclosure Vulnerability (CSCvf20218)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Unified
Communications Manager (CUCM) running on the remote device is affected
by an information disclosure vulnerability. Please see the included
Cisco BID and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180418-ucm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?58c37f05");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf20218");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvf20218.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0266");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver         = get_kb_item_or_exit("Host/Cisco/CUCM/Version");
ver_display = get_kb_item_or_exit("Host/Cisco/CUCM/Version_Display");
fix_display = FALSE;
app_name    = "Cisco Unified Communications Manager (CUCM)";

if (ver =~ "^10\." && ver_compare(ver:ver, fix:'10.5.2.17148.1', strict:FALSE) < 0)
  fix_display = "10.5(2.17148.1)";
else if (ver =~ "^11\.0" && ver_compare(ver:ver, fix:'11.0.1.25091.1', strict:FALSE) < 0)
  fix_display = "11.0(1.25091.1)";
else if (ver =~ "^11\.5" && ver_compare(ver:ver, fix:'11.5.1.14071.1', strict:FALSE) < 0)
  fix_display = "11.5(1.14071.1)";
else if (ver =~ "^12\.0" && ver_compare(ver:ver, fix:'12.0.1.22011.1', strict:FALSE) < 0)
  fix_display = "12.0(1.22011.1)";
else if (ver =~ "^12\.5" && ver_compare(ver:ver, fix:'12.5.0.98000.267', strict:FALSE) < 0)
  fix_display = "12.5(0.98000.267)";

if (!fix_display)
  audit(AUDIT_INST_VER_NOT_VULN, app_name, ver_display);

order  = make_list('Cisco bug ID', 'Installed release', 'Fixed release');
report = make_array(
  order[0], "CSCvf20218",
  order[1], ver_display,
  order[2], fix_display
);
report = report_items_str(report_items:report, ordered_fields:order);
security_report_v4(extra:report, port:0, severity:SECURITY_WARNING);
