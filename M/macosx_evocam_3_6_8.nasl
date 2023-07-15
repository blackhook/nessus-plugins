#TRUSTED 3b7232db40e7fc22a00d2031a99fbf7397722325268d5c518d8d81718ba4e33c9af5f6b69bf75387af941985aa3c701576a27d84238e625b5aedcef983909484d57e90df55ce2064d5c24acb30aa323d53a7355032eeb958930523ad93269348931cc90a0491717d1999cbdca0665fca7d24373c63292ca41c42058b9e3f6b92dde23b0ebeff50202ed592858637a8cc4c9467d1b6fd8a804841b3374367fbac4e075502231257fe7ba37e283129752fd34185c8afbcec9fdc5b58e34e03346aeed6224cf39e42ac22b1c4053fb5c0483e8244880010467d29f3c023d6cb98cb4e64a54c36529a6f9b252ec38d1c0486ae007916d0b6b11e6568fbd8cc6efd3d567b32196536c079b82966ba8fdb75eedc26a9b5397ae0884ed8658a841593393e61c598356ab617db91c1eb45da047ae9565f320282ad283cd31cb2600b471d63cf79602f58f4ed46169c54feb82d8b6f175594d06960b66c38711ad66ccaa85cccb3eaa642faa84c1b50100199c454cbfdefdd235764472a4938905fa615ba2b2f6246923f2a50dfcc04779f39598765c054dac7b53beb78fcd882c662f56d3dadc4b51dd9c5e7e8b2ab91156ec7494a5e55750c463e9dcfc4f7dd613fca50315ec5a082ef7f94577e062cc11111915571ef700637cc594209b7dc59de7174a74f1c8130a99c5e59cfc74bf5292b22e6b1731c1704e042418eeae523df2d66
#TRUST-RSA-SHA256 60c936485c77017185e0e90b3de55bd6f719f1b7f0ad5deabbef774d13a6701365d4a39d5e6d0aea007bd3bd0462f03d7cdaace4c4ec8c397226884cdded54e18d8fdcfbdf21ee4c2e14ab691e13beaa40e57341ed949a1073b5ecf78ff242806af29b45055adb7c2de89fa36c887bacac147f4421c7ff0fc61b0b3247f71c12511e540ff79aafa999cdae9beecf3a53ade21fcd8d2fa29373de9e395c2c22d76ad6251d64c87f89563717a640d34e68a23e6bac01bd31283384b481c83bd018cd6b17c4b90b0e9c00a58e52c527ca0ca2eee0410315d453fad10ff35e952471178d35aec3178efafea6f6c259f1ad4b3e04102290a8d532a85be17eb73791a8096cc4b2b60f2e490d87c34f4b867c8f90b93f80aa3acbb23d57ab0ed6cbc3268f2a72b590cb0404f00e12d189e54ee12c7957d9ccec24148318d77ea6fb6d77a2b5702a2e5c0e88b4a624ebab797096f19047e4d66a6144dfc22db25279172e2ecae9f7d65f7b15b7ed8c69d8793d1f744e3c9e32b5202708cbdf40115f8bc144c8dc33dad287aaf846ecf693cc570cbc808a96769f10f30be952e4da6dc8053417d2762e92ba1856566f0b5e32e92d7d70132193b8a00fb7af62a7040b14c0f1ff18bea3e71798e09823b2c1407f5aa27f2a0027eaecaa030a160dc98ab55d2f36c6cead7042ee60276584fca76302b6abcb930effe86ee7c0b95032215e35
#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");


if (description)
{
  script_id(47682);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id("CVE-2010-2309");
  script_bugtraq_id(40489);
  script_xref(name:"EDB-ID", value:"13735");

  script_name(english:"EvoCam 3.6.6 / 3.6.7 Web Server GET Request Overflow");
  script_summary(english:"Checks version of EvoCam");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an application that may be susceptible to a remote
buffer overflow attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of EvoCam installed on the Mac OS X host is either 3.6.6
or 3.6.7.  Such versions reportedly contain a buffer overflow in the
Web Server component. 

Using an overly long GET request, an unauthenticated remote attacker
may be able to leverage this vulnerability to execute arbitrary code
on the remote host subject to the privileges under which the
application runs."
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to EvoCam 3.6.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-2309");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MacOS X EvoCam HTTP GET Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "http_version.nasl");
  script_require_keys("Host/MacOSX/packages");
  script_require_ports("Services/www", 8080, "Settings/ParanoidReport");

  exit(0);
}

if (!defined_func("bn_random")) exit(0);

include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(1, "The 'Host/MacOSX/packages' KB item is missing.");


# Unless we're paranoid, make sure the service is enabled.
if (get_kb_item("global_settings/report_paranoia") != 'Paranoid')
{
  found = FALSE;
  ports = add_port_in_list(list:get_kb_list("Services/www"), port:8080);

  foreach var port (ports)
  {
     soc = open_sock_tcp(port);
     if (soc)
     {
      send(socket:soc, data:http_get(item:"/", port:80));
      res = recv(socket:soc, length:1024);

      if (
        strlen(res) &&
        (
          "<title>EvoCam</title>" >< res ||
          '<applet archive="evocam.jar" code="com.evological.evocam.class"' >< res
        )
      ) found = TRUE;
      close(soc);
    }
    if (found) break;            
  } 
  if(!found) exit(0, "The EvoCam web server is not listening on the remote host.");
}


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
  if (buf !~ "^[0-9]") exit(1, "Failed to get the version - '"+buf+"'.");

  buf = chomp(buf);
  return buf;
}


plist = "/Applications/EvoCam.app/Contents/Info.plist";
cmd = string(
  "cat '", plist, "' | ",
  "grep -A 1 CFBundleShortVersionString | ",
  "tail -n 1 | ",
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
);
version = exec(cmd:cmd);
if (!strlen(version)) exit(1, "Can't get version info from '"+plist+"'.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] == 3 && 
  ver[1] == 6 && 
  (ver[2] == 6 || ver[2] == 7)
)
{
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet')
  {
    report = 
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.6.8\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since EvoCam "+version+" is installed.");
