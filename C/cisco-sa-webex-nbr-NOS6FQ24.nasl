##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142880);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/16");

  script_cve_id("CVE-2020-3573", "CVE-2020-3603", "CVE-2020-3604");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu53451");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu53534");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu55885");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu55901");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu59610");
  script_xref(name:"CISCO-SA", value:"cisco-sa-webex-nbr-NOS6FQ24");
  script_xref(name:"IAVA", value:"2020-A-0529-S");

  script_name(english:"Cisco Webex Network Recording Player and Cisco Webex Player Arbitrary Code Execution Vulnerabilities (cisco-sa-webex-nbr-NOS6FQ24)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Webex Network Recording Player for Windows and Cisco Webex player for
Windows are affected by multiple arbitrary code execution vulnerabilities due to insufficient validation of certain
elements of a Webex recording that is stored in the Advanced Recording Format (ARF) or Webex Recording Format (WRF). An
unauthenticated attacker can exploit these, by sending a user a malicious ARF or WRF file through a link or email
attachment and persuading the user to open the file, in order to execute arbitrary code on the affected system with the
privileges of the targeted user.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webex-nbr-NOS6FQ24
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e2d7e71");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu53451");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu53534");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu55885");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu55901");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu59610");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvu53451, CSCvu53534, CSCvu55885, CSCvu55901,
CSCvu59610");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3604");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/13");

  script_set_attribute(attribute:"agent", value:"windows");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:webex_network_recording_player");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:webex_player");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("webex_player_installed.nasl");
  script_require_keys("installed_sw/WebEx ARF/WRF Player");

  exit(0);
}

include('vcf.inc');

app = 'WebEx ARF/WRF Player';
get_kb_item_or_exit('installed_sw/' + app);

app_info = vcf::get_app_info(app:app);

if (app_info.version =~ "^40\.6")
  fix = '40.6.11';
else
  fix = '40.8.0';

constraints = [
  { 'min_version' : '0.0', 'fixed_version' : fix }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

