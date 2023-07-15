#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40987);
  script_version("1.17");
  script_cvs_date("Date: 2018/11/15 20:50:22");

  script_cve_id("CVE-2009-3232");
  script_bugtraq_id(36306);
  script_xref(name:"Secunia", value:"36620");

  script_name(english:"Random password for 'root' account");
  script_summary(english:"Tries to SSH as root with a random password.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote system has an authentication bypass vulnerability."
  );
  script_set_attribute(attribute:"description", value:
"Nessus was able to login to the remote host as 'root' via SSH with a
random password.

A remote attacker can exploit this to gain access to the affected
host, possibly at an administrative level.

This may be due to a known issue with some versions of Ubuntu's
libpam-runtime package when used in a non-default manner, although
Nessus has not tried to verify the underlying cause.");
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.launchpad.net/ubuntu/+source/pam/+bug/410171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/828-1/"
  );
  script_set_attribute(attribute:"solution", value:
"If the remote host is running Ubuntu, upgrade to libpam-runtime
1.0.1-4ubuntu5.6 / 1.0.1-9ubuntu1.1 or later.

Otherwise, make sure the root account is secured with a strong
password, and SSH is configured to require authentication.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(287);

  # when this issue was posted to the Ubuntu bug tracker
  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2009-2018 Tenable Network Security, Inc.");

  script_dependencie("find_service1.nasl", "ssh_detect.nasl", "account_check.nasl");
  script_require_ports("Services/ssh", 22);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("default_account.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = check_account(login:rand_str(length:8), password:rand_str(length:8));
if ( port ) exit(0, "Any login/password pair is accepted?");

account = 'root';
password1 = string(SCRIPT_NAME, unixtime());
password2 = string(SCRIPT_NAME, rand());

affected = FALSE;
ssh_ports = get_service_port_list(svc: "ssh", default:22);
foreach port (ssh_ports)
{
  port = check_account(login:account, password:password1, port:port, svc:"ssh");
  if (port)
  {
    affected = TRUE;
    if (report_paranoia == 2)
    {
      security_report_v4(port:port, severity:SECURITY_HOLE, extra:default_account_report());
      exit(0);
    }
    else
    {
      # If paranoia isn't high, try to login again using a different password, just to
      # make sure the system really will let us login with any password
      port = check_account(login:account, password:password2, port:port, svc:"ssh");
      if (port)
      {
        affected = TRUE;
        security_report_v4(port:port, severity:SECURITY_HOLE, extra:default_account_report());
      }
    }
  }
}
if(affected) exit(0);

telnet_ports = get_service_port_list(svc: "telnet", default:23);
foreach port (telnet_ports)
{
  port = check_account(login:account, password:password1, port:port, svc:"telnet");
  if (port)
  {
    affected = TRUE;
    if (report_paranoia == 2)
    {
      security_report_v4(port:port, severity:SECURITY_HOLE, extra:default_account_report());
      exit(0);
    }
    else
    {
      # If paranoia isn't high, try to login again using a different password, just to
      # make sure the system really will let us login with any password
      port = check_account(login:account, password:password2, port:port, svc:"telnet");
      if (port)
      {
        affected = TRUE;
        security_report_v4(port:port, severity:SECURITY_HOLE, extra:default_account_report());
      }
    }
  }
}
if(!affected) audit(AUDIT_HOST_NOT, "affected");