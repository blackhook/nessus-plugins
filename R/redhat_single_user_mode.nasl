#TRUSTED 97b7d714be27d72fa07f884d51733b1e3734b610cc36f6fe0a0bf61cd7915d23527dc5e811be9949ff4b0515d435d5a41fa52495a60731fbabbdf68568f852e937aed7e3b0b6bbdf29c2157b5f9173c5e34417e1f9d66e58fecdf6ab939babfc979c5606de527fe9605abb8062854ee0a25e46fa914d273209497986e67303e9509aeb103d63606ca5afbc0867160e23bcac7658ab7f9a8aec2be3d270576b81820e835d660716b30da664982c64bb2abd64b57ee4dd9be70028f225adb82d33e44e7b95b7ac0fec771c79d2153aa38910ee828e691b4893b08966390ce4f5323d5c9016ab6e887e3597bc7da9d4de3acfd645587f1d8dc37b65228a4926e709c62ec718e5a9742614d135ec5d9ca0de4537eaa5f1ddeee0ae75607857e2d5c0f9b58269fdc73e547098eb6c97a6eadc1db2d81d37623234b757ecd6f810a85d9eb2e899248db6eed15d4f9993cc261a67506b56bb1e5fb5a320c1634b4dff39e626bd329a7af2de2339290367aafa8d943d2dfcd37809e8a3a45cb84b471188ec41965301b1c0300d3dc3e29424ca3ec266c8e9520d3f159b08febc487333e1de261d909065e301d5eb7eafb90e4402e12f6b9258b15842644b7789cc0ac5fee460fb793d95fa465ce5c65c475a9d868996a061ae906eec92552b0ef27c5f7c4af083e70d50d3539f8233b761365836ce3a935c07d99ca268e46d7ec08c33a6

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(105412);
 script_version("1.8");
 script_cve_id("CVE-2000-0219");
 script_bugtraq_id(1005);

 script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

 script_name(english:"Red Hat Single User Mode");
 script_summary(english:"Checks for authorization with single user mode.");

 script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host can be accessed via single user mode without root password.");
 script_set_attribute(attribute:"description", value:
"The remote Red Hat system does not have authorization for single user mode enabled.
An attacker with physical access can enter single user mode with root privileges via the
LILO or GRUB boot menu.");
 #https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/deployment_guide/sec-single-user_mode
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14b14125");
 script_set_attribute(attribute:"solution", value:
"Edit '/etc/sysconfig/init' and set the 'SINGLE' configuration value to 'sulogin'.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/21");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:linux");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Red Hat Local Security Checks");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/local_checks_enabled", "Host/RedHat/release");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

redhat_release = get_kb_item("Host/RedHat/release");
if (isnull(redhat_release) || "Red Hat" >!< redhat_release) audit(AUDIT_OS_NOT, "Red Hat");
if ("Red Hat Enterprise Linux" >< redhat_release) audit(AUDIT_INST_VER_NOT_VULN, "Red Hat Enterprise Linux");

os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:redhat_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");


os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (islocalhost())
{
  if (!defined_func("pread")) exit(1, "'pread()' is not defined.");
  info_t = INFO_LOCAL;
}
else
{
  info_t = INFO_SSH;
  ret = ssh_open_connection();
  if (!ret) exit(1, "Failed to open an SSH connection.");
}

vuln = FALSE;
res1 = info_send_cmd(cmd:"cat /etc/sysconfig/init | grep SINGLE");

if (res1 =~ '^SINGLE=/sbin/sushell')
  vuln = TRUE;

if(vuln)
{
  report = "According to '/etc/sysconfig/init' it is possible to gain root access (without password)";
  report += ' in single user mode:\n  ' + res1;
  security_report_v4(severity:SECURITY_HOLE, extra:report, port:0);
}
else
  audit(AUDIT_HOST_NOT, "affected");
