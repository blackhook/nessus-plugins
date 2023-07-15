#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140269);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/10");

  script_cve_id("CVE-2020-3541");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu19065");
  script_xref(name:"CISCO-SA", value:"cisco-sa-webex-media-znjfwHD6");
  script_xref(name:"IAVA", value:"2020-A-0402");

  script_name(english:"Cisco Webex Teams for Windows Information Disclosure Vulnerability (cisco-sa-webex-media-znjfwHD6)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Webex Teams is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webex-media-znjfwHD6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?90c9fec8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu19065");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu19065");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3541");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:webex_teams");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_webex_teams_installed_win.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Webex Teams");

  exit(0);
}

include('vcf.inc');

app = 'Webex Teams';

app_info = vcf::get_app_info(app:app, port:port, win_local:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [{ 'fixed_version': '3.0.15711.0' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);


