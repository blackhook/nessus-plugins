#TRUSTED 3aecc3bc71e52a28754489d07930862e7a8bc5119b778d860d785f3ae566a499938fedaf4ef219c192ce01c9becc2c2b79f423aa42d00ee4c399177e534f53e298ec7974796fd4ddc674315e5ebd19d5efd0874abba0ead2b9308b35ab829a488b3838da216c4de7fda26ce40d2514cf8a0eacc0df44faa23c95a77479d11c5a622949a127ba259d78688c2dfd60a5c136cd91bc46242725283b1fb3244b4f0fbd0379508714f153a6dfab34ea3d211111c960a283ddcd8d8344441f0858249f0d246ec5e3d649d964a7010918af49c4583b08183c88bfa4f23f049711e387854b1d6c5b42b54940e36805f919dafb214c89aa6e1e939e07c3b347952652e2430e8614d11b8584d0d51ae89b7964311fcd9e7a269dd3b3412415490b86163dae33e03963d707de6e75ce065e462fd859cc4467447786c03072bf7161dab380d8b52f638a5e8b44bb2781602d064a8e07ae4f3adb96bbd6a4d6b0304b1f469e3fa9ab1bf98d7abc495afe97f2d947f0d26f29c580024fdcf136cf0228c01369e88b33c5891cb7dd791e04d3dfca40ac726fb1e75d5b6f081cb6c497dda0944db0afffa0d60fc77d4e7fca778ae86d84a4aa06f6d71983ae6c049ff2382cfb81af666ff2c81bf48d2a94dbec29dc0eb1d5f13a31dff7e92db9cbdd786e995fba872243e99d4e3c315ea6cfa8caf3d010220caba496c1a359a15b205c0956332fe3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108810);
  script_version("1.7");
  script_cvs_date("Date: 2019/04/04 10:19:47");

  script_name(english:"Microsoft Windows Default Credentials (PCI wordlist)");
  script_summary(english:"Microsoft Windows SMB brute force.");

  script_set_attribute(attribute:"synopsis", value:
"Credentials for the remote Windows operating system can be discovered.");
  script_set_attribute(attribute:"description", value:
"An SMB account on the remote Microsoft Windows host uses a common
password for one or more accounts. These accounts may be used to gain
access to the remote operating system and allow remote command
execution. These accounts may belong to the Local Administrators or
Domain Administrators groups.");
  script_set_attribute(attribute:"solution", value:
"Assign a different password to this account as soon as possible.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"default credentials");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_login.nasl");
  script_require_keys("Settings/PCI_DSS", "SMB/name", "SMB/transport");
  script_exclude_keys("Settings/PCI_DSS_local_checks", "SMB/any_login", "SMB/not_windows", "global_settings/supplied_logins_only");
  script_require_ports(139, 445);
  exit(0);

  script_timeout(900);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");
include("pci_password_dict.inc");

if (get_kb_item("SMB/not_windows")) audit(AUDIT_OS_NOT, "Windows");
if (get_kb_item("SMB/any_login")) exit(0, "The remote host authenticates users as 'Guest'.");

if (!get_kb_item("Settings/PCI_DSS")) audit(AUDIT_PCI);

if (get_kb_item("Settings/PCI_DSS_local_checks"))
  exit(1, "This plugin only runs for PCI External scans.");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

var logins = get_pci_login_list(platform:'WINDOWS');

name = kb_smb_name();
port = kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

kb_domain = kb_smb_domain();
if (empty_or_null(domain)) kb_domain = ".";

info = '';
for (j=0; j<max_index(logins); j++)
{
  login = logins[j];
  user = login['username'];
  pass = login['password'];
  domain = kb_domain;

  soc = open_sock_tcp(port);
  if (!soc) audit(AUDIT_SOCK_FAIL, port);

  session_init(socket:soc, hostname:name);
  rc = NetUseAdd(login:user, password:pass, domain:domain);
  NetUseDel(close:FALSE);
  if (rc == -1 && domain != ".")
  {
    domain = ".";
    rc = NetUseAdd(login:user, password:pass, domain:domain);
    NetUseDel();
  }
  close(soc);
  if (rc == 1)
  {
    info +=
      '\n' +
      '\n  Login    : ' + user +
      '\n  Password : ' + pass;
    if (domain != ".") info += '\n  Domain   : ' + domain;
    info += '\n';
  }
}
if (info != '')
{
  report = '\nNessus was able to gain access using the following credentials :';
  report += info;
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_HOST_NOT, "affected");
