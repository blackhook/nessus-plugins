##
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2021/03/19. Deprecated by cisco-sa-webex-nbr-NOS6FQ24.nasl
##

include('compat.inc');

if (description)
{
  script_id(142879);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/29");

  script_cve_id("CVE-2020-3573", "CVE-2020-3603", "CVE-2020-3604");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu53451");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu53534");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu55885");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu55901");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu59610");
  script_xref(name:"CISCO-SA", value:"cisco-sa-webex-nbr-NOS6FQ24");
  script_xref(name:"IAVA", value:"2020-A-0529-S");

  script_name(english:"Cisco Webex Meetings Arbitrary Code Execution Vulnerabilities (cisco-sa-webex-nbr-NOS6FQ24) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated as it's a duplicate of cisco-sa-webex-nbr-NOS6FQ24.nasl (plugin ID 142880)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webex-nbr-NOS6FQ24
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e2d7e71");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu53451");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu53534");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu55885");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu55901");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu59610");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3604");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:webex_meetings");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_webex_meetings_win_installed.nbin");
  script_require_keys("installed_sw/Cisco Webex Meetings");

  exit(0);
}
exit(0, "This plugin has been deprecated. Use cisco-sa-webex-nbr-NOS6FQ24.nasl (plugin ID 142880) instead.");
