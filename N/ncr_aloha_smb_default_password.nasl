#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108716);
  script_version("1.2");
  script_cvs_date("Date: 2018/11/15 20:50:27");

  script_name(english:"NCR Aloha POS SMB Default Credentials");
  script_summary(english:"Attempts to authenticate with default credentials.");

  script_set_attribute(attribute:"synopsis", value:
"An account on the remote NCR Aloha POS host uses a default password.");
  script_set_attribute(attribute:"description", value:
"The remote NCR Aloha POS device is running with default credentials
(aloha / aloha). A remote, unauthenticated attacker could exploit this
to take control of the system.");
  # https://community.softwaregrp.com/t5/custom/page/page-id/HPPSocialUserSignonPage?redirectreason=permissiondenied&referer=https%3A%2F%2Fcommunity.softwaregrp.com%2Ft5%2FArchived-Security-Research-Blog%2FHacking-POS-Terminal-for-Fun-and-Non-profit%2Fba-p%2F278079
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d03390cf");
  script_set_attribute(attribute:"solution", value:
"Change the default password of this account.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:ncr:aloha_pos");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:ibertech:aloha_pos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018 Tenable Network Security, Inc.");

  script_dependencies("smb_login.nasl", "ncr_aloha_pos_web_detect.nbin");
  script_require_keys("SMB/name", "SMB/transport", "installed_sw/NCR Aloha POS");
  script_exclude_keys("SMB/any_login", "SMB/not_windows", "global_settings/supplied_logins_only");
  script_require_ports(139, 445);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");
include("install_func.inc");

get_install_count(app_name:"NCR Aloha POS", exit_if_zero:TRUE);

if (get_kb_item("SMB/not_windows")) audit(AUDIT_OS_NOT, "Windows");
if (get_kb_item("SMB/any_login")) exit(0, "The remote host authenticates users as 'Guest'.");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# SMB port and socket tests
name = kb_smb_name();
port = kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

domain = kb_smb_domain();
if (empty_or_null(domain)) domain = ".";

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

# Attempt to login with default credentials
login = "aloha";
pass  = "aloha";

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
NetUseDel(close:FALSE);

# Login failed with specified domain; try local domain name '.'
if (rc == -1 && domain != ".")
{
  domain = ".";
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
  NetUseDel();
}
if (rc != 1)
  audit(AUDIT_HOST_NOT, "affected");

# Report
report = '\n  Nessus was able to gain access using the following credentials :' +
         '\n' +
         '\n  Login    : ' + login +
         '\n  Password : ' + pass;
if (domain != ".")
  report += '\n  Domain   : ' + domain;
report += '\n';

security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
