#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134981);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/31");

  script_cve_id("CVE-2018-0264");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh85410");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh85430");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh85440");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh85442");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh85453");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh85457");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180502-war");

  script_name(english:"Cisco WebEx Advanced Recording Format RCE (cisco-sa-20180502-war)");

  script_set_attribute(attribute:"synopsis", value:
"The video player installed on the remote Windows host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco WebEx Network Recording Player for Advanced Recording Format (ARF) on the remote host is affected
by a vulnerability which allows a remote, unauthenticated attacker to execute arbitrary code on the system of a
targeted user by sending the user a link or email attachment with a malicious ARF file and persuading the user to follow
the link or open the file.
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180502-war
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dff96338");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version of WebEx Network Recording Player referenced in Cisco advisory cisco-sa-20180502-war.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0264");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:webex_advanced_recording_format_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("webex_player_installed.nasl");
  script_require_keys("installed_sw/WebEx ARF/WRF Player");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

app = 'WebEx ARF/WRF Player';
get_kb_item_or_exit('installed_sw/' + app);

app_info = vcf::get_app_info(app:app);

if (app_info['Product'] != 'Webex ARF Player')
  audit(AUDIT_HOST_NOT, 'an affected product');

constraints = [
  { 'min_version' : '0.0', 'fixed_version' : '31.23.4' },
  { 'min_version' : '32', 'fixed_version' : '32.12' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
