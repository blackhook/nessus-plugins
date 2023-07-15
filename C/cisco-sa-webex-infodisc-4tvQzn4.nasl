##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143475);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/04");

  script_cve_id("CVE-2020-3441");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu44356");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu48356");
  script_xref(name:"CISCO-SA", value:"cisco-sa-webex-infodisc-4tvQzn4");
  script_xref(name:"IAVA", value:"2020-A-0550-S");

  script_name(english:"Cisco Webex Meetings Information Disclosure (cisco-sa-webex-infodisc-4tvQzn4)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Webex Meetings is affected by a information disclosure vulnerability.
This vulnerability is due to insufficient protection of sensitive participant information. An unauthenticated, remote
attacker could exploit this vulnerability by browsing the Webex roster. A successful exploit could allow the attacker
to gather information about other Webex participants, such as email address and IP address, while waiting in the lobby.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webex-infodisc-4tvQzn4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?39cd3c9b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu44356");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu48356");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvu44356, CSCvu48356");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3441");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:webex_meetings");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_webex_meetings_win_installed.nbin", "macosx_cisco_webex_meetings_desktop_app_installed.nbin");
  script_require_keys("installed_sw/Cisco Webex Meetings", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

# Detection has no ability to detect MR3 security patches and we don't check slow channel
# mentioned in part of the advisory.
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

app_info = vcf::get_app_info(app:'Cisco Webex Meetings');
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  {'min_version': '0', 'max_version': '40.11.3', 'fixed_version': 'See vendor advisory'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
