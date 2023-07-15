#TRUSTED 8927b5e19d4c2df236a38d63d11522f3bebae9a06c06a077569caf6351fcc86a35595cc53d9e9a7f439964ed1b711ecc00a4d73ca262c4ae34b614319ca6eab26f15a9df69e96c067a8184b704292957799b897b37e25b8a3ea77746512727a1142c36379be107b6be995c46f78e34cbd5d7267dcb25f0072c381e5861f33b7b7300e2571e4434276ff04023ee54a8e330f08712dfac245fa1b34dd3cba5be7b9340d5dad75888f17fb3c5764ff4b95478fb575aff7b5db1e5e7e1815cdd7f39c5d058c9cf65b512bf3fbe8d1e5326bf2b0eb0115cfb634252ebb407088d3956ccac69002e955c07703ba2fd53ae09bc495685709b0153bfdd72c1b82ae6426081b4f76c15bc1a26ecde2d9daae9b56fea3b1eb7957cbeb6f53fa6ea654f95a1f71150f830f19f599a449a6de125916dee338a2304b070bacfce7155408cdea5e1b4b50309763902859ceeddea2f4d791dfdde892d31488111fb7d627aca2fad966b506b1ed02da748044ba79276eb0d1c9b1392b108ca6f66eeb6f86b44ee1e15b7fe875428740ff0c43a4048435d2ee7cc79ecf2921fbdb7883e3723dda6fa915354a9c6d4d624ae69e86e09727ff2840bf1d89d5a413ef7799db0a4d096191f76d060fc479ab54a7a9094b4a0c2cbe64b669e1a96e35a83eea49053e4a3328b37a4280d554e20eeae33f416a545b3f34e2b8e221b4444575613c5783b08b6
#TRUST-RSA-SHA256 009dc1186ba711adfabf5c8679acb61c64c4742cf8f70c654bf2e21f6eda916fab6531bc7b225d7ea1208fbbe4fe3f77ed9d740a28fde8a0011648fbd36cd02fa846dce40f4ed17a31e0b39fbb5ae25f0e3b376600a399628bf4ce1638052aa024ff542c52f2c4da371e64e735ddece6468dff00c001552f55f925898237d21f9d9bf5f5d23fc935f7b85cbd62bb9532295a0dfa5322ec47cbc5ce62f7f7d45ac0598834a09f92cf64fdf2c6a9cff72165499df4fdfe4626cad521b7e0b4ede637b5d5b60848a5409f189c3fd541a32416055fea3b55239de896abdeee5ef7920d2563c2eaab93b42b84e0c2404c4994f0a37ec0a02a4515e09fc628af2c5d653f88453ae7de55e7be9a17cf0b9ef560fb5fbf8b7e5110852c266104151ed8afe7cf3a11b409e1f4b50a5a766702900168ad1d0df0b348342f3a35473988b399bffe5bcdf53a337cd5da0ed15100286637c07625024e201dc4bb85eb9a91817fc9e76f2f93986b123b409c9b8c8458b4a4ef11e624bcc840382e880ed83cbc75ec4d6187a1726181dd6310bc0fde7d20e2021ea366241571f812f885e6911d13cd63923eb6f8fb2d0e69c5a3b273b7f3a5b70a2d903b65593b61cba5e83351d609ee19debdae6407af496dbe6bb199bffb641e1ea528fe1010a11d0f8d44562afa0b8eca2a6a17f71b916d8f1792c7afa3a2247c4e3bf0f08758c3b329346a35
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100571);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/21");

  script_name(english:"suidperl Privilege Escalation (PROCSUID)");
  script_summary(english:"Checks for an installation of suidperl.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The suidperl application is installed on the remote host. It is,
therefore, affected by a privilege escalation vulnerability that
allows a local attacker to gain root privileges.

PROCSUID is one of multiple Equation Group vulnerabilities and
exploits disclosed on 2017/04/08 by a group known as the Shadow
Brokers.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/x0rz/EQGRP");
  script_set_attribute(attribute:"solution", value:
"Remove the affected software.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Manual analysis of the vulnerability");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/01");

  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:perl:suid");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2022 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('ssh_func.inc');
include('ssh_globals.inc');

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

vuln = 0;

  distros = make_list(
    "Host/AIX/lslpp",
    "Host/AmazonLinux/rpm-list",
    "Host/CentOS/rpm-list",
    "Host/Debian/dpkg-l",
    "Host/FreeBSD/pkg_info",
    "Host/Gentoo/qpkg-list",
    "Host/HP-UX/swlist",
    "Host/MacOSX/packages",
    "Host/Mandrake/rpm-list",
    "Host/McAfeeLinux/rpm-list",
    "Host/OracleVM/rpm-list",
    "Host/RedHat/rpm-list",
    "Host/Slackware/packages",
    "Host/SuSE/rpm-list",
    "Host/XenServer/rpm-list"
  );

check_pat = INJECTION_PATTERN;

installed_package = "";

foreach pkgmgr (distros)
{ 
  pkgs = get_kb_item(pkgmgr);
  if(!isnull(pkgs) && ("suidperl" >< pkgs || "perl-suid" >< pkgs)) 
  {
    match = pregmatch(pattern:"(perl-suid\s*(?:perl)?[^\\|\s]+)", string:pkgs);
    if(!empty_or_null(match) && !empty_or_null(match[1])) installed_package = match[1];
    vuln++;# make it vuln
    break;
  }
}

ret = ssh_open_connection();
if (!ret) audit(AUDIT_FN_FAIL, 'ssh_open_connection');

error = NULL;
p_dir = ssh_cmd(cmd:"which perl");
if(!empty_or_null(p_dir))
{ 
  if(p_dir =~ check_pat) exit(0, "Supplied path string contains disallowed characters.");

  cmd = "dirname " + chomp(p_dir);
  p_dir = ssh_cmd(cmd:cmd);
  p_dir = chomp(p_dir);

  error = ssh_cmd_error();
  if(!empty_or_null(error))
  {
    if(error =~ "dirname:\s*missing operand") audit(AUDIT_NOT_INST, "perl");
    else exit(0, "The following error was encountered : "+error);
  } 
 
}
if(empty_or_null(p_dir)) audit(AUDIT_NOT_INST, "perl");
if(p_dir =~ check_pat) exit(0, "Supplied path string contains disallowed characters.");

error = NULL;
cmd = "ls -l " + p_dir + "/sperl*";
lsperl = ssh_cmd(cmd:cmd);
error = ssh_cmd_error();
ssh_close_connection();

if(!empty_or_null(error))
{
  if(error =~ "No such file or directory") audit(AUDIT_NOT_INST, "suidperl");
  else exit(0, "The following error was encountered : "+error);
}

if(!empty_or_null(lsperl) && lsperl =~ p_dir+"/sperl")
{
  if (lsperl =~ "^.rws")
  {
    pattern = "("+ p_dir + "/sperl.*)\s*$";
    path = pregmatch(pattern:pattern, string:lsperl);
    path = path[1];
    vuln ++;
  }
  else audit(AUDIT_HOST_NOT, "affected. suidperl was found but its setuid bit is not set");
}

if(vuln)
{
  report = 'The remote host has a vulnerable version of suidperl installed: \n';
  if(!empty_or_null(installed_package)) report += '\n  Installed Package : ' + installed_package;
  if(!empty_or_null(path)) report += '\n  Path              : ' + path + '\n';
  security_report_v4(severity:SECURITY_HOLE, extra:report, port:0);
}
else audit(AUDIT_NOT_INST, "suidperl");
