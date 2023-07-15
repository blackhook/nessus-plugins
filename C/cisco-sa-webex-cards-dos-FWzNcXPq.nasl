#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(133407);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/08");

  script_cve_id("CVE-2020-3131");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs25793");
  script_xref(name:"CISCO-SA", value:"cisco-sa-webex-cards-dos-FWzNcXPq");
  script_xref(name:"IAVA", value:"2020-A-0046");

  script_name(english:"Cisco Webex Teams for Windows Adaptive Cards Denial of Service (cisco-sa-webex-cards-dos-FWzNcXPq)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Webex Teams is affected by a denial of service vulnerability. 
An authenticated, remote attacker can exploit this, by crafting a malicious adaptive card file and sending it to
a Webex Teams client user, causing the client to crash continuously.

Please refer to the Cisco BIDs and Cisco Security Advisory for more
information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webex-cards-dos-FWzNcXPq
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ca9a0f69");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs25793");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Webex Teams client version 3.0.14234.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3131");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:webex_teams");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

constraints = [
    { 'min_version': '3.0.13131.0', 'fixed_version':'3.0.14234.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
