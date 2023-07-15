#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(85651);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2015-4303",
    "CVE-2015-4316",
    "CVE-2015-4317",
    "CVE-2015-4318",
    "CVE-2015-4319",
    "CVE-2015-4320"
  );
  script_bugtraq_id(
    76322,
    76347,
    76350,
    76351,
    76353,
    76366
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv12333");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv12338");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv12340");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv40396");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv40469");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv40528");

  script_name(english:"Cisco TelePresence VCS Expressway Series 8.5.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Cisco
TelePresence Video Communication Server (VCS) Expressway running on
the remote host is affected by multiple vulnerabilities :

  - A command injection vulnerability exists in the web
    framework component due to insufficient validation of
    user-supplied input. An authenticated, remote attacker
    can exploit this, via a specially crafted request, to
    inject arbitrary commands that execute at the 'nobody'
    user privilege level. (CVE-2015-4303)

  - An access vulnerability exists in the Mobile and Remote
    Access (MRA) endpoint-validation feature due to improper
    validation of the phone line used for registration. An
    authenticated, remote attacker can exploit this, via a
    crafted Session Initiation Protocol (SIP) message, to
    register their phones and impersonate legitimate users.
    (CVE-2015-4316)

  - A denial of service vulnerability exists due to
    insufficient handling of malformed authentication
    messages. An unauthenticated, remote attacker can
    exploit this, via a crafted authentication packet with
    invalid variables, to cause a denial of service
    condition. (CVE-2015-4317)

  - A denial of service vulnerability exists due to
    insufficient handling of malformed GET request messages.
    An unauthenticated, remote attacker can exploit this,
    via a crafted packet with invalid variables, to cause a
    denial of service condition. (CVE-2015-4318)

  - A security bypass vulnerability exists in the Password
    Change functionality due to insufficient enforcement in
    the authorization process. An authenticated, remote
    attacker can exploit this, via a specially crafted
    packet, to reset arbitrary active-user passwords.
    (CVE-2015-4319)

  - An information disclosure vulnerability exists in the
    Configuration Log File component due to the inclusion of
    sensitive information in certain log files. An
    authenticated, remote attacker can exploit this to view
    the sensitive information in the log files.
    (CVE-2015-4320)");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuv12333");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuv12338");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuv12340");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuv40396");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuv40469");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuv40528");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=40433");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=40441");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=40442");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=40443");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=40444");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=40445");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs
CSCuv12333, CSCuv12338, and CSCuv12340. For Cisco bug IDs CSCuv40396,
CSCuv40469, and CSCuv40528 contact the vendor for a fix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-4303");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_video_communication_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server_software");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2022 Tenable Network Security, Inc.");

  script_dependencies("cisco_telepresence_video_communication_server_detect.nbin");
  script_require_keys("Cisco/TelePresence_VCS/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version  = get_kb_item_or_exit("Cisco/TelePresence_VCS/Version");
fullname = "Cisco TelePresence Device";

if (version =~ "^8\.5\.2($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : See vendor' +
             '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else audit(AUDIT_DEVICE_NOT_VULN, fullname, version);
