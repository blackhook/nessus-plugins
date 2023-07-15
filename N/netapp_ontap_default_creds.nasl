#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(92541);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"NetApp OnTap OS Default Credentials");

  script_set_attribute(attribute:"synopsis", value:
"An account on the remote host uses a known default password.");
  script_set_attribute(attribute:"description", value:
"The remote device is a NetApp OnTAP OS device that uses a set of
known, default credentials. An attacker who is able to connect to the
service can use these credentials to gain control of the device.");
  script_set_attribute(attribute:"solution", value:
"Log in to the remote host and change the default login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:netapp:data_ontap");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Default Unix Accounts");

  script_copyright(english:"This script is Copyright (C) 2016-2022 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("default_account.inc");
include("global_settings.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

creds = [['admin', 'netapp123'],
         ['root',  'netapp123'],
         ['root', 'netapp!123']];
# second root login with alt password found in:
# https://library.netapp.com/ecm/ecm_download_file/ECMP1234780

affected = FALSE;
ssh_ports = get_service_port_list(svc: "ssh", default:22);
foreach port (ssh_ports)
{
  report = "";
  foreach cred (creds)
  {
    ret = check_account(login: cred[0], password: cred[1], port:port, svc:"ssh");
    if (ret)
    {
      report += '\n  Login : ' + cred[0] +
                '\n  Pass  : ' + cred[1] +
                '\n';
      affected = TRUE;
      if (!thorough_tests) break;
    }
  }
  if(report)
  {
    report = '\n' + 'Nessus was able to gain access using the following credentials :' +
             '\n' + report;
    security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
  }
}
if(affected) exit(0);

telnet_ports = get_service_port_list(svc: "telnet", default:23);
foreach port (telnet_ports)
{
  report = "";
  foreach cred (creds)
  {
    ret = check_account(login: cred[0], password: cred[1], port:port, svc:"telnet");
    if (ret)
    {
      report += '\n  Login : ' + cred[0] +
                '\n  Pass  : ' + cred[1] +
                '\n';
      affected = TRUE;
      if (!thorough_tests) break;
    }
  }
  if(report)
  {
    report = '\n' + 'Nessus was able to gain access using the following credentials :' +
             '\n' + report;
    security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
  }
}
if(!affected) audit(AUDIT_HOST_NOT, "affected");