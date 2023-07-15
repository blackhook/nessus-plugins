#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(42148);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2009-4741");
  script_bugtraq_id(36459);

  script_name(english:"Skype Extras Manager Unspecified Vulnerability (uncredentialed check)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Skype client is affected by a security vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Skype installed on the remote host ships with a version
of the 'Skype Extras Manager' which is older than 2.0.0.67. 

The remote version of this package contains an unspecified security
vulnerability. 

Note this only affects Skype for Windows.");
  # https://dev.skype.com/#head-21c1b2583e7cc405f994ca162d574fb15a6e986b
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a19c0fc");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Skype version 4.1.0.179 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:skype:skype");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2022 Tenable Network Security, Inc.");

  script_dependencies("skype_version.nbin", "smb_nativelanman.nasl");
  script_require_keys("Services/skype");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


# The flaw only affects Windows hosts.
if (report_paranoia < 2)
{
  os = get_kb_item("Host/OS/smb");
  if (!os) exit(0, "The 'Host/OS/smb' KB item is missing.");
  if ("Windows" >!< os) exit(0, "The issue only affects Windows hosts.");
}


port = get_service(svc:"skype", exit_on_fail:TRUE);

# nb: "ts = 910091106" => "version = 4.1.0.179"
ts = get_kb_item_or_exit("Skype/"+port+"/stackTimeStamp");
if (ts > 0 && ts < 910091106) security_warning(port);
else exit(0, "The Skype client listening on port "+port+" is not affected based on its timestamp ("+ts+").");

