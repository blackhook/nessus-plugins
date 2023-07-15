#TRUSTED 412858620869b9c10b6b7e34b8e9ba7a4b3d3806b41d07d74b2afeb2d80d5ea3234ca8eb36a464a9ae1547b6f7a77d509cfd939f7e449b7c29ea7c83292b60995a9189871c0045dc28f3111f5b4e91cd58d3bb9cb8189478a6b6b9849a95b695e63facf42da2d60afada061a3a7bba7c2f5064940ec2c1c9cbd08e932ca2b2f4897f6d62020ca1ae973273df620948778c5fb1ab9ec38f2f916f17a0c3923292938a5ad08e922f197f80ec2c25ed2939d29ec66429506376b90b233fe47cd2a72455ac7fea5ceae3c0464e51816070f3c50f1f6e4a2bba9fcf8ccd317a6c3326d0089ca86cedddf601c27e2582dc3e3cecc356e93b02e704c0ba645bdb90b8419b2e6ca51db193777b979295b6ed8da3e204d04f2ccf521e121209b11e28df2bdf160a29519b97d03b52eb182d84ee2b8646dce6917a8961797ef881781fbf11288971615f673273a37feb56af60ebec3012cfd73ae8ee50ca1ed43d21a9ae216b7ac528fb535f63be08778b030bdd6ad3fbc3eb5b5b8c1a4a6d5cfd5b4752318011861f65748c17dd765cc36fe47945081bb75e4b85741f7e6272ee3465eb60ccfdd5d8f9438697941f2d4cd3aa0d65a07551ce566deeb27efbdaf486a971cc4f53298915ee2d36857caeca276eab2e0bd95cda3c0baec0d76160f18e386fcd95bf502ba3c83d3251696ae8173b35f169ea391165174dc16492b7c9741b75f4
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70195);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2009-5116");
  script_bugtraq_id(38489);
  script_xref(name:"EDB-ID", value:"14818");

  script_name(english:"McAfee LinuxShield <= 1.5.1 nailsd Daemon Remote Privilege Escalation");
  script_summary(english:"Logs in with SSH and checks the version of McAfee LinuxShield");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote host is affected by a privilege escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee LinuxShield installed on the remote host is 1.5.1
or earlier.  As such, it potentially is affected by a privilege
escalation vulnerability because it does not properly authenticate
clients.  An attacker able to log into the remote host can leverage this
vulnerability to authenticate to the application's 'nailsd' daemon and
do configuration changes as well as execute tasks subject to the
privileges with which the 'nailsd' daemon operates.");
  script_set_attribute(attribute:"see_also", value:"http://sotiriu.de/adv/NSOADV-2010-004.txt");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2010/Mar/26");
  script_set_attribute(attribute:"solution", value:
"Upgrade to LinuxShield 1.5.1 if necessary and install hotfix
HF550192");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:linuxshield:1.5.1");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2013-2022 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if ("Linux" >!< get_kb_item_or_exit("Host/uname")) audit(AUDIT_OS_NOT, "Linux");

hotfixable_ver = "1.5.1";
hotfix = "HF550192";
cat_config_cmd = "cat /opt/NAI/LinuxShield/etc/config.xml";
cat_hfversion_cmd = "cat /opt/NAI/LinuxShield/etc/HF-Version";

port = kb_ssh_transport();

ret = ssh_open_connection();
if (ret == 0) audit(AUDIT_SVC_FAIL, "SSH", port);

cat_config_output = ssh_cmd(cmd:cat_config_cmd, nosh:TRUE, nosudo:FALSE);
if (
  isnull(cat_config_output) ||
  !eregmatch(pattern:"<InstalledPath>__NAILS_INSTALL__</InstalledPath>", string:cat_config_output)
)
{
  ssh_close_connection();
  audit(AUDIT_NOT_INST, "McAfee LinuxShield");
}

matches = eregmatch(pattern:"<Version>([0-9]+\.[0-9]+\.[0-9]+)</Version>", string:cat_config_output);
if (isnull(matches))
{
  ssh_close_connection();
  audit(AUDIT_VER_FAIL, "McAfee LinuxShield");
}

ver = matches[1];

# We treat a missing HF-Version file and an empty one the same way
cat_hfversion_output = ssh_cmd(cmd:cat_hfversion_cmd, nosh:TRUE, nosudo:FALSE);
if (isnull(cat_hfversion_output)) cat_hfversion_output = "";
ssh_close_connection();

# If this is 1.5.1, has the hotfix been applied?
if (ver == hotfixable_ver && egrep(pattern:"^" + hotfix + "$", string:cat_hfversion_output)) audit(AUDIT_PATCH_INSTALLED, hotfix);

# If this is not 1.5.1, is it > 1.5.1?
if (ver_compare(ver:ver, fix:hotfixable_ver, strict:FALSE) == 1)  audit(AUDIT_INST_VER_NOT_VULN, "McAfee LinuxShield", ver);

if (report_verbosity > 0)
{
  vuln_report += '\n  Version       : ' + ver +
                 '\n  Fixed version : ' + hotfixable_ver + " with " + hotfix + " applied" +
                 '\n';
  security_warning(port:0, extra:vuln_report);
}
else security_warning(0);
