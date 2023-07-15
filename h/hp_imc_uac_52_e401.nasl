#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(65256);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2012-5211");
  script_bugtraq_id(58964);

  script_name(english:"HP Intelligent Management Center User Access Manager Unspecified Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a user access management application installed that
is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the HP Intelligent Management Center
User Access Manager installed on the remote host is affected by an
unspecified information disclosure vulnerability.");
  # https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-c03689276-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?935b94fc");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/525928/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-13-058/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP Intelligent Management Center User Access Manager 5.2
E401 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-5211");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:intelligent_management_center");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hp_imc_detect.nbin");
  script_require_ports("Services/activemq", 61616);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Figure out which port to user
port = get_service(svc:'activemq', default:61616, exit_on_fail:TRUE);

version = get_kb_item_or_exit('hp/hp_imc/'+port+'/components/iMC-UAM/version');

# All versions 5.1 and earlier
if (version =~ '^([0-4]\\.|5\\.(0\\-|1[^\\-]))')
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.2-E402' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'HP Intelligent Management Center User Access Manager', port, version);
