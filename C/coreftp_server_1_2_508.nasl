#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72661);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/27");

  script_cve_id("CVE-2014-1215");
  script_bugtraq_id(65692);

  script_name(english:"Core FTP Server < 1.2 Build 508 lstrcpy Overflow Code Execution");
  script_summary(english:"Checks the version of Core FTP Server.");

  script_set_attribute(attribute:"synopsis", value:
"The FTP server running on the remote host is affected by a code
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Core FTP running on the remote host is prior to 1.2
build 508. It is, therefore, affected by buffer overflow conditions
in the RegQueryValueExA() and lstrcpy() functions due to improper
validation of user-supplied input when reading data from the
config.dat file and/or from the Windows Registry. A local attacker can
exploit this to cause a denial of service condition or to execute
arbitrary code.");
  # https://www.portcullis-security.com/security-research-and-downloads/security-advisories/cve-2014-1215/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?12696fbd");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2014/Feb/172");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Core FTP version 1.2 build 508 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-1215");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:coreftp:coreftp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("coreftp_server_detect.nbin");
  script_require_keys("installed_sw/Core FTP Server");
  script_require_ports("Services/ftp", 21);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

appname = 'Core FTP Server';
install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);

port = install["path"];
source = install["version_source"];
version_build = install["version_build"];
fullver = install["fullversion"];

fix = "1.2.508";
if (ver_compare(ver:fullver, fix:fix, strict:FALSE) == -1)
{
  report =
    '\n  Version source    : ' + source +
    '\n  Installed version : ' + version_build +
    '\n  Fixed version     : 1.2 Build 508' +
    '\n';
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'Core FTP Server', port, version_build);
