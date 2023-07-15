#TRUSTED 9bc5fa4d7a4dba091f6b8a0050d9862f3c9471398908129ccc76f625f538874f81b575d1cadf26ca60257e10d9c03a21436fd0ec131996da7bd286ce5c60e370af836031d8901a88ea00786909c697d3b38890ed9d66144a9ae8a6d818d3b88ca9b539de02caae61c28f6148649c5d4c53694acb498ad1ad4a5b1f831a3d72b25c6717ae32d18500edcd174119f7e1609f307a5b21921c809079794487b4107120420996fe8dd468222066a37971087075acb32d22797de4108c148d41d77b15fb9ac89e603b3ae58ba6d44160215d55477bdc045ad28b7f0fdd1be19affdd2c023b0d5710e00d6e5406c665ab03c34ab0a5eb9a4b37dc7b254469de934bb38a6c5cfd93f7f8ea35709f6705811acf5b08d692b8b9c41d56732e4fb8edf771b3886fdc12f0a66544106797b4b286a660463a014123843bdb8827397c2d0c4df23e297a78344ec1f3912f0dcd56343f83c4bd0638223a40edcca1a02a1175a9fa1cdc4cf4ccacfd59a145c33f085e6a35ad258b1fbb9cb72392eec8ea63a4a6b0d05f11874dbdf47c99b874fe8afb3be7a7b4fc0a925c1a326306643246f5d732f2c0b2bd4bd32285eb950b6f4ef4c3157aeae13d5916e1f8f5e40e620d974890ad1d6a5794a23d76bd1e7ccf374c8fe70269d546c7a1cc951a79a14c0b75abddc26de17eccabe1f59dd9bddbb1860e8ff8f8f2cbc581382f2a0fdd5134ec4c70

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101166);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_name(english:"RHEL / CentOS 6.x (64-bit) Malicious Kernel Module Detection (OutlawCountry)");
  script_summary(english:"Attempts to detect OutlawCountry kernel module install.");

  script_set_attribute(attribute:"synopsis", value:
"A malicious kernel module is potentially installed on the remote Linux
host.");
  script_set_attribute(attribute:"description", value:
"According to diagnostic indicators, the remote Red Hat Enterprise
Linux or CentOS host may have a malicious kernel module known as
OutlawCountry installed. OutlawCountry creates a hidden netfilter
table that allows an authenticated attacker to covertly override
existing netfilter/iptables firewall rules.

Note that only RHEL and CentOS 6.x operating systems running kernel
version 2.6.32 (64-bit) are reportedly affected. OutlawCountry was
disclosed on 2017/06/30 by WikiLeaks as part of their ongoing
'Vault 7' series of leaks.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/solutions/3099221");
  script_set_attribute(attribute:"solution", value:
"Refer to the referenced Red Hat solution article.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/30");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2022 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

redhat_release = get_kb_item("Host/RedHat/release");
centos_release = get_kb_item("Host/CentOS/release");

if(isnull(redhat_release) && isnull(centos_release))
  audit(AUDIT_OS_NOT, "Red Hat Enterprise Linux / CentOS");

combined = redhat_release + centos_release;
arch = get_kb_item("Host/cpu");

if("64" >!< arch || "release 6" >!< combined ||  combined !~ "(Red Hat Enterprise Linux|CentOS)")
  audit(AUDIT_OS_NOT, "64 bit Red Hat Enterprise Linux / CentOS 6.x");

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

res1 = info_send_cmd(cmd:"iptables -t dpxvke8h18 -L -nv");
res2 = info_send_cmd(cmd:"lsmod");

if (info_t == INFO_SSH) ssh_close_connection();

vuln = FALSE;
if("Chain PREROUTING" >< res1 && "nf_table" >< res2)
  vuln = TRUE;

if(!vuln)
  exit(0, "The remote host does not appear to be affected.");

report = 
  '\nBased on the output of "iptables -t dpxvke8h18 -L -nv", the host is' +
  '\nrunning a hidden filter table that may indicate a malicious kernel' +
  '\nmodule is installed (according to unverifiable reports from WikiLeaks' +
  '\nand the media).' +
  '\n' +
  '\nCommand output :\n\n' + res1 + '\n';

security_hole(port:0, extra:report);

