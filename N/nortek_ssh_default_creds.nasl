#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(175106);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/04");

  script_name(english:"Nortek Default SSH Credentials");
  script_summary(english:"Attempts to log in to the remote host.");

  script_set_attribute(attribute:"synopsis", value:
"An account on the remote host uses a known default password.");
  script_set_attribute(attribute:"description", value:
"The remote device is a Nortek device that uses a set of known,
default credentials. An attacker who is able to connect to the
service can use these credentials to gain control of the device.");
  script_set_attribute(attribute:"solution", value:
"Log in to the remote host and change the default login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/04");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Default credential score."); 

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:niceforyou:linear_emerge_e3_access_control_firmware");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Default Unix Accounts");

  script_copyright(english:"This script is Copyright (C) 2018-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include('default_account.inc');

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

var creds = [['root', 'davestyle']];

var affected = FALSE;
var ssh_ports = get_service_port_list(svc: "ssh", default:22);
var report = '';

foreach var port (ssh_ports)
{
  var report = "";
  foreach cred (creds)
  {
    var ret = check_account(login:cred[0], password:cred[1], port:port, svc:"ssh", unix:TRUE);

    if (ret)
    {
      report += '\n  Login : ' + cred[0] +
                '\n  Pass  : ' + cred[1] +
                '\n';
      affected = TRUE;
    }
  }
  if (report)
  {
    report = '\n' + 'Nessus was able to gain access using the following default credentials:' +
             '\n' + report;
    security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
  }
}

if (!affected) audit(AUDIT_HOST_NOT, "affected");
