#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110053);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Oracle TNS Listener VSNNUM Version Remote Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"A database service listening on the remote host discloses version
information remotely.");
  script_set_attribute(attribute:"description", value:
"It was possible to extract the version number of the remote Oracle TNS
(Transparent Network Substrate) listener remotely by sending an
unauthenticated request to the TNS listener service operating on this
port. This information could aid an attacker.

Note that the version of the TNS listener does not necessarily reflect
the version of the Oracle database it provides access to.");
  script_set_attribute(attribute:"solution", value:
"Restrict access to the database to allowed IPs only.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_detect.nbin");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/oracle_tnslsnr", 1521);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_service(svc:"oracle_tnslsnr", default:1521, exit_on_fail:TRUE);

version = get_kb_item_or_exit("Oracle/"+port+"/VSNNUM_version");
vsnnum = get_kb_item("Oracle/"+port+"/VSNNUM");

report =
  '\nThe following TNS listener version was able to be extracted remotely :'+
  '\n\n  Version : ' + version + '\n';

if(vsnnum) report += '  VSNNUM  : ' + vsnnum + '\n';

security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
