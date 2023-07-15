#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139599);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/29");

  script_cve_id("CVE-2020-3463");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu05825");
  script_xref(name:"CISCO-SA", value:"cisco-sa-webex-mttngs-xss-3VbdxDuF");
  script_xref(name:"IAVA", value:"2019-A-0273-S");

  script_name(english:"Cisco Webex Meetings Reflected XSS (cisco-sa-webex-mttngs-xss-3VbdxDuF)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Webex Meetings is prior to 40.6.0. It is, therefore, affected by a
Reflected Cross-Site Scripting (XSS) vulnerability. An unauthenticated, remote attacker can exploit this
vulnerability by persuading a user to click a malicious link. A successful exploit allows the attacker to execute
arbitrary script code in the context of the affected interface or access sensitive, browser-based information.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webex-mttngs-xss-3VbdxDuF
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5311ec3d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu05825");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu05825");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3463");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/14");

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

include('vcf.inc');

app_name = 'Cisco Webex Meetings';

app_info = vcf::get_app_info(app:app_name);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'fixed_version' : '40.6.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});

