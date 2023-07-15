#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(168824);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/16");

  script_cve_id("CVE-2018-15715");

  script_name(english:"Zoom Client for Meetings < 4.1.34460.1105 Vulnerability (ZSB-18001)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Zoom Client for Meetings installed on the remote host is prior to 4.1.34460.1105. It is, therefore,
affected by a vulnerability as referenced in the ZSB-18001 advisory.

  - A vulnerability in the Zoom client could allow a remote, unauthenticated attacker to control meeting
    functionality such as ejecting meeting participants, sending chat messages, and controlling participant
    microphone muting. If the attacker was also a valid participant in the meeting and another participant was
    sharing their desktop screen, the attacker could also take control of that participant's keyboard and
    mouse. The vulnerability is due to the fact that Zoom's internal messaging pump dispatched both client
    User Datagram Protocol (UDP) and server Transmission Control Protocol (TCP) messages to the same message
    handler. An attacker can exploit this vulnerability to craft and send UDP packets which get interpreted as
    messages processed from the trusted TCP channel used by authorized Zoom servers. Zoom released client
    updates to address this security vulnerability. Users can help keep themselves secure by applying current
    updates or downloading the latest Zoom software with all current security updates from
    https://zoom.us/download . (CVE-2018-15715)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://explore.zoom.us/en/trust/security/security-bulletin/?filter-cve=&filter=&keywords=ZSB-18001
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?19d6981a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zoom Client for Meetings 4.1.34460.1105 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15715");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/15");

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

vcf::check_granularity(app_info:app_info, sig_segments:3);

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'fixed_version' : '4.1.34460.1105' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
