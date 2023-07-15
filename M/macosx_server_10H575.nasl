#TRUSTED 9d2c79e0046f701fcddcb23ac797e277c0265b6563df0e2ab4b4ad8cf45baab8a40fa2366040920d318da4794d65a2d07ede6fdc2d63fbeb87021edb0e083d051e19ba7a245403f4055fd1a3184d9cb23ca456b65a27ed51e4b08496530cd7ddf14cec2da4f0dbab272de0d19471a4491bd6ddde74f0c4744f404e916f10d78c9c1ed272f7f237176836d75a2a5196b8d9f9d08eafc138453832fa8839779851550fac990556c8a2316a0c29d8e48e1072b2b74dd442986ad3baa10e291ea9eff768c95f732d46bc71eef050fe90e81ccfd3f8c4a447d0c40b7db90653888abf90b36f9276c7d5143a77b59b1df4f8c406e9eca60fcce3ff85fc9a243eb9ff9cba358e719f7d4f6760392a5d77508155296e3cb7950df0edb734121fd258d94c27f28dc3f6e88cb64eb2468d31bab71468fd62930b10661eccf670d05a4a85afb3211692d7551608e0cb5b333a1e54de36b52630802e6b6b3dabe476b1f335300f561426fb6a4e6eb1e8067acca78f99a9bc6ae4262c79b549fb9635f1af5ba7dcc0b9a5d91f2fa7f5ef730c6adbe4826c6e53c9a80d6427c3d92075930c5ae42596079d353497b9fdc31fd03fc49b29cde86255ffb9645469ccf019c4b3456a96054309810301b5db03a35b760c72d65197dd488022af3d14e6965105ac15ba1d02e545f909afb913227219ee24b68b3b4b62c365ec60cf20d85c14bdebb774
#TRUST-RSA-SHA256 1124879fca89909a5513fbe46daf11c7344bec2b752e859fb08db573de5e5283f50dc0db85f6db67c861160ae22d2c4561b7c2b788726a6125d98ca10c3662643d4da23c1297e79a6c8a6d9282f8593a0df69951055fa4a962b8e1c0612603fd8b13a2a02162a7cabdb045ef921d9057c08081d9abf00bb70f0f91b5a3042fa675612fb49b87e5c23b139c1c86ec7c0ecb6653c83745be0dfed50c1e82ea37d3488e2d5f874646c2e6de3cf5134ae76d91d61ac510c8723bcdc03754b7ef04fba6d1183d9c61bd2a11e93dc94df998be4ba37ad2063c9585ec8df71517a55821b78972ada81aa99cec0ed42ec9df8df3a663f29082f9b6852e100b85dd4e1effc2e498c5578f7cf75bc9ab13ffa0fb655346532fcd4fa0ae18febb609680f99fba42ab4cccdc0337f20594e25a0144d962813e09645edd3a5baedb422de26c15aba4c7298140dd8d94a65f3d59a63ce9df2bc23e97f2fdf70f04fc144a5c081fbe05e512b752b6abfdc31e979cd140ea406c6c8d278c402fd079924cc3eef37fb532f1e2ede34773b48ed794654f582f91af6404bcc388fb6be0d4f367c478852fa9ca8b8bf20e499ceb4bc884b55dd4bed217babaed5d5fdad86eab5df685c8aaed8d8c1359827efd8f8425ddb4ebcc2f1ba4d7c1501e43f2706d97883da96c7cf11f44f662c40d9c3f0e97758b53da6eec7eb07684be8675eaa2e3a9d9df7e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50681);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id("CVE-2010-4011");
  script_bugtraq_id(44874);

  script_name(english:"Mac OS X Server v10.6.5 (10H575)");
  script_summary(english:"Checks ProductBuildVersion in /System/Library/CoreServices/ServerVersion.plist");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an application that may be affected by an
information disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A memory aliasing issue in Dovecot's handling of user names in Mac OS
X Server v10.6.5 may result in a user receiving mail intended for
other users. 

Note that this vulnerability arises only on Mac OS X Server systems
when Dovecot is configured as a mail server."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT4452"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2010/Nov/msg00001.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Mac OS X Server v10.6.5 (10H575) or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-4011");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2023 Tenable Network Security, Inc.");

  script_dependencies("macosx_server_services.nasl");
  script_require_keys("Host/uname", "MacOSX/Server/Version");

  exit(0);
}

if (!defined_func("bn_random")) exit(0);

include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

function exec(cmd)
{
  local_var ret, buf;

  if (islocalhost())
    buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = ssh_open_connection();
    if (!ret) exit(1, "ssh_open_connection() failed.");
    buf = ssh_cmd(cmd:cmd);
    ssh_close_connection();
  }

  return buf;
}


uname = get_kb_item("Host/uname");
if (!uname) exit(0, "The 'Host/uname' KB item is missing.");

# Mac OS X 10.6 only.
if (!egrep(pattern:"Darwin.* 10\.", string:uname)) exit(0, "The remote Mac is not running Mac OS X 10.6.");


version = get_kb_item("MacOSX/Server/Version");
if (!version) exit(1, "Failed to retrieve the Mac OS X Server version.");
if ("Server 10.6" >!< version) exit(0, "The host is running "+version+" and thus not affected.");


# And check it.
#
# nb: Apple says only 10H574 is affected.
if ("(10H574)" >< version)
{
  # Unless we're paranoid, make sure Dovecot is being used for mail.
  gs_opt = get_kb_item("global_settings/report_paranoia");
  if (gs_opt && gs_opt != 'Paranoid')
  {
    status = get_kb_item("MacOSX/Server/mail/Status");
    if (!status) exit(1, "Failed to retrieve the status of the 'mail' service.");

    if ("RUNNING" >!< status)
      exit(0, "The mail service is not running, and thus the host is not affected.");

    cmd = 'serveradmin settings mail:postfix:mailbox_transport';
    buf = exec(cmd:cmd);
    if (!buf) exit(1, "Failed to run '"+cmd+"'.");

    if (!eregmatch(pattern:'mailbox_transport *= *"dovecot"', string:buf)) 
      exit(0, "The mail service does not use Dovecot, and thus the host is not affected.");

    report_trailer = '';
  }
  else report_trailer = 
    '\n' +
    'Note, though, that Nessus did not check whether the mail service is\n' +
    'running or Dovecot is in use because of the Report Paranoia setting in\n' +
    'effect when this scan was run.\n';

  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet')
  {
    version = strstr(version, "Server ") - "Server ";

    report = 
      '\n  Installed system version : ' + version + 
      '\n  Fixed system version     : 10.6.5 (10H575)\n';
    if (report_trailer) report += report_trailer;

    security_warning(port:0, extra:report);
  }
  else security_warning(0);

  exit(0);
}
else exit(0, "The remote host is not affected since Mac OS X Server build version "+version+" is installed.");
