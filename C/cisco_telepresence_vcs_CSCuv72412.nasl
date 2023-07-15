#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(88527);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2015-6376");
  script_bugtraq_id(77678);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv72412");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151120-tvcs");

  script_name(english:"Cisco TelePresence VCS 8.5.1 Unspecified XSRF (cisco-sa-20151120-tvcs)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an unspecified cross-site request
forgery vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Cisco
TelePresence Video Communication Server (VCS) running on the remote
host is affected by an unspecified cross-site request forgery (XSRF)
vulnerability. A remote attacker can exploit this by tricking a user
of a web application into following a malicious link.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151120-tvcs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7646665d");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuv72412");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco TelePresence VCS version 8.5.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-6376");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_video_communication_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server_software");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2022 Tenable Network Security, Inc.");

  script_dependencies("cisco_telepresence_video_communication_server_detect.nbin");
  script_require_keys("Cisco/TelePresence_VCS/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version  = get_kb_item_or_exit("Cisco/TelePresence_VCS/Version");
fullname = "Cisco TelePresence Device";

if (version =~ "^8\.5\.1($|[^0-9])")
{
  set_kb_item(name:"www/0/XSRF", value:TRUE);
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : 8.5.3 or later' +
             '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else audit(AUDIT_DEVICE_NOT_VULN, fullname, version);
