##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161760);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/02");

  script_cve_id(
    "CVE-2022-22784",
    "CVE-2022-22785",
    "CVE-2022-22786",
    "CVE-2022-22787"
  );

  script_name(english:"Zoom Client < 5.10.0 Attack Chain Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Zoom Client for Meetings for Windows installed on the remote host is prior to 5.10.0.  It is,
therefore, affected by multiple vulnerabilities.

  - The Zoom Client for Meetings (for Android, iOS, Linux, MacOS, and Windows) before 
    version 5.10.0 failed to properly parse XML stanzas in XMPP messages. (CVE-2022-22784)
    
  - The Zoom Client for Meetings (for Android, iOS, Linux, MacOS, and Windows) before 
    version 5.10.0 failed to properly constrain client session cookies to Zoom domains.
    (CVE-2022-22785)
    
  - The Zoom Client for Meetings for Windows before version 5.10.0 and Zoom Rooms for 
    Conference Room for Windows before version 5.10.0, fails to properly check the 
    installation version during the update process. (CVE-2022-22786)
    
  - The Zoom Client for Meetings (for Android, iOS, Linux, macOS, and Windows) before 
    version 5.10.0 fails to properly validate the hostname during a server switch 
    request. (CVE-2022-22787)

Taken together, these vulnerabilities allow a unauthenticated, remote attacker can exploit this, via stringing these
vulnerabilities together with a MitM attack, to cause Remote Code Execution without any user interaction.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://explore.zoom.us/en/trust/security/security-bulletin");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zoom Client for Meetings 5.10.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22786");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:zoom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:meetings");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("zoom_client_for_meetings_win_installed.nbin");
  script_require_ports("installed_sw/Zoom Client for Meetings", "installed_sw/zoom");

  exit(0);
}

include('vcf.inc');

var app_info = NULL;

if (get_kb_item('installed_sw/Zoom Client for Meetings'))
  app_info = vcf::get_app_info(app:'Zoom Client for Meetings', win_local:TRUE);
else
  app_info = vcf::get_app_info(app:'zoom');

constraints = [{ 'fixed_version' : '5.10.0' }];

vcf::check_granularity(app_info:app_info, sig_segments:3);

vcf::check_all_backporting(app_info:app_info);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

