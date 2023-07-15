#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(85649);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2015-4315");
  script_bugtraq_id(76352);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv31853");

  script_name(english:"Cisco TelePresence VCS Expressway 8.5.3 XML External Entity (XXE) Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an XML External Entity (XXE) injection
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Cisco
TelePresence Video Communication Server (VCS) Expressway running on
the remote host is affected by an XML External Entity (XXE) injection
vulnerability due to insufficient validation of declared document type
definitions (DTD) stored externally. An authenticated, remote attacker
can exploit this, via a specially crafted XML file, to cause a denial
of service condition or to read arbitrary files.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuv31853");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=40446");
  script_set_attribute(attribute:"solution", value:
"Contact the vendor for a fix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-4315");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/13");
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

if (version =~ "^8\.5\.3($|[^0-9])")
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
