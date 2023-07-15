#TRUSTED 67015f552ffd309687bc6ce41c70e47127f1462be58cd384f498eda79dbee97e5e8db09489a0dd43ec533f8e30b31323824b53f27e47e78a79e36a8b316dca487eac2d07a92173d67bef6c54f5c4cef8822e139556af64a4989cd362242283fe70d35b262c5e02e26c9962ebc54d780974ea27fbf3df9d920409a07c24599ff5ad35131d134ea4a4682ab905b8e511212632219db5e4c86f42aa40e13e6b470fc2047c00b5662e9c3b2b25b708d97e5f9aeaadbb228b9a1d94129620d557b35766ad4a3e7534e1a859a9525f454351ca29e2cb50ad7ec3fdbf428a03cfff048df60de5dacf59ceb263984f735b094c3f8342e91abb0c7906ef635a937f08b6c84f5c653ee8d8cc8aa660c3b7a10cd3625672a81b8a9f0c44ff990b60122f894ac8c6776f10cd248d3fa03c5a12c00f55c31e58f84ac706dd58506f6af03f086f8e6242508923824af2b28234fb9b3f4448c098abdea4f5e785da15e0c275f4322e250d88ed9e456fcc3e074b32774d82748c62dc7ccef195de61497c7067f8a517a7d149df73a0073c4cbe889790825c4037c87e49e01249f5a4c1374bf9c2e4f3e7361b771e6b4b9a792ed462ecd58619387e29a5f59fe18b9551e8d16d87a9c6fe5920f7d8756aeb633d029dd43cdf6702f716d7bf7233a9796bf147749ac66c19845c10f9b285e8269ffcdb325245f261157ea1b814d464419efdc114d5da
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70731);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2013-3834");
  script_bugtraq_id(63138);

  script_name(english:"Oracle Secure Global Desktop ttaauxserv Remote Denial of Service (credentialed check)");
  script_summary(english:"Checks if patch is installed");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has software installed that is affected by a denial
of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of Oracle Secure Global Desktop
installed that has an unspecified denial of service vulnerability in
the ttaauxserv binary that may be triggered by a remote attacker."
  );
  # http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac29c174");
  script_set_attribute(
    attribute:"solution",
    value:
"Install the patched binary per the instructions in the vendor's
advisory."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:virtualization_secure_global_desktop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2022 Tenable Network Security, Inc.");

  script_dependencies("oracle_secure_global_desktop_installed.nbin");
  script_require_keys("Host/Oracle_Secure_Global_Desktop/Version");

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

version = get_kb_item_or_exit("Host/Oracle_Secure_Global_Desktop/Version");
if (version != "5.00.907") audit(AUDIT_INST_VER_NOT_VULN, version);

# this check is for Oracle Secure Global Desktop packages built for Linux platform
uname = get_kb_item_or_exit("Host/uname");
if ("Linux" >!< uname) audit(AUDIT_OS_NOT, "Linux");

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

cmd = "dd if=/opt/tarantella/bin/bin/ttaauxserv bs=10000 count=359 | md5sum";
cmd1 = "dd if=/opt/tarantella/bin/bin/ttaauxserv bs=10000 skip=360 | md5sum";

res = info_send_cmd(cmd:cmd);
if (strlen(res) == 0)
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(0, 'No results returned from "' + cmd + '" command ran on remote host.');
}

if (res !~ "^[0-9a-f]{32}([ ]|$)")
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(0, 'Unexpected output from "' + cmd + '"');
}

res1 = info_send_cmd(cmd:cmd1);
if (info_t == INFO_SSH) ssh_close_connection();

if (strlen(res1) == 0) exit(0, 'No results returned from "' + cmd1 + '" command ran on remote host.');
if (res1 !~ "^[0-9a-f]{32}([ ]|$)") exit(0, 'Unexpected output from "' + cmd1 + '"');

if (
  "e8490e71847949c9cd161db9f9eece95" >!< res ||
   "bfcc1282a99455ffeab15a348a1cf3f8" >!< res1
) audit(AUDIT_INST_VER_NOT_VULN, "Oracle Secure Global Desktop");

if (report_verbosity > 0)
{
  report = '\n  Version          : ' + version +
           '\n  Unpatched binary : /opt/tarantella/bin/bin/ttaauxserv\n';
  security_warning(port:0, extra:report);
}
else security_warning(0);
