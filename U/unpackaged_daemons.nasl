#TRUSTED 0ce02f64f441eb94e6ab14c028e45267ae52876ed9f4b9d4c1054b5fc39146d50c4a14eccf13a7e83b8ca1ffd34a9a4de6aa7e8d9b776102c5f29e81c66f909a970bb1681267134324f0dc10f265d062756efeefc55e34ccb4a2e6923ed6cc3a05463f103b8d2c3f82e79fe874521aa5ba890bb47d52be9119441925f9cdd63ea582f23e85116b930bf1be5c092a811734ab7f693e15706cfab4ffb20f93161c8207494556d15aea30eefa7825ac9ad109fc0a17f64457f469dcb12cbb858b60fdf9351c51f025bfbebd667cec59b4bfa00c0640bec88b09247b086eb21afb8fd607c0b7761c2bf8404e48b9b8dd3916404b0653648998873ab4db168d7df35d2b76a0346c0d105ac8e225798bbc628255d16610380986cc4323586e679849cb6912c3e759c788ccbffaca9bf17ebafbf9e2e9ab1178c1c0618b993727b9818bd0030481dc7586758a34e7d7e62e0b54eb14e01a5d80d2d8013a1a165be35bbb5cc0f87835e68180b2babbfddea8e3db85d7b714318bdcc023153012f527b47fc2cd5b57910cb14f052284af00ba9102d99d361d65a40188d0c0dcb66c667b00e28540d0c7f101a22d551d575fc93b98b7068584080542c613ba01ec1582cf02823b3fdff5d0011b20e735dd6a18d6d7d4e2bd5295e0d1b5393ab90b8b694ac02ba6fb76becbdecdda6c18377cfbf30c22262b72a095a58797247d66b8e8b59d
#TRUST-RSA-SHA256 321072d0d77348b54564361b643ae514560866bfe7a093ecc64c058a4b117730ea6fcffcfd0f6d919829e21ade8756ca23229fc394a60abfdcf8e66c6ee42a748612357f09bcbd9e9291f8a222b3441d21c15bb91feaea420c41e9d89db6f3610df9a3e17eee4d72ad3633e8ffb956c058dd3524fb087039c3688d5f85fb0a76b48e00f0bf5db7c9423043353c66e0173c353edea4733067e23d41b9cf9910f2d98da335e6d1952284e0e82edbd6193e02dec09f9b81d0f1168196623d64372b47a293025306b8f58e1f4953ce8ea38350ee6616f923bc707315edc6279417e9232d19cc7302cb1b10f5bbc561ce587d4bfed89c4f37f2e8f6a1f084ef5fe176b42e953e93b9989bbec1a9f3c35e942f0c473477f4b28a2ae1df88a7beabf4d49e9487cd776d57cff2fe5bb5019bc25d0d84c10c8250e6d4fc3f22e53778d67da3bbbcee47efa735ea7376c67cf747c8ebca892774d4cf7143ed2b876de2b2269505deae11780d239957d460459dd4957cad8adc575a860137e82204c1d8e55760176f8f6caf4997e845378f64063f5d1c8e6b320bcbeb0ba79b85528c73e9c04c235419b21cc1ac50ac4b54060cc448896328d5c645eaca2083ea7f50b4b09d16e3956a7664c2b4543f35f2002bfaf15423f7c0ef409d30e1249b540cbacff1b1e50e1f60d1ce333111a5e243fbbebff42efbaf14f65dbdb05c684e8269b951
#
# (C) Tenable Network Security, Inc.
#


include('compat.inc');

if(description)
{
 script_id(33851);
 script_version("1.24");
 script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/21");

 script_name(english: "Network daemons not managed by the package system");

 script_set_attribute(attribute:"synopsis", value:
"Some daemon processes on the remote host are associated with programs
that have been installed manually." );
 script_set_attribute(attribute:"description", value:
"Some daemon processes on the remote host are associated with programs
that have been installed manually.

System administration best practice dictates that an operating
system's native package management tools be used to manage software
installation, updates, and removal whenever possible." );
 script_set_attribute(attribute:"solution", value:
"Use packages supplied by the operating system vendor whenever
possible.

And make sure that manual software installation agrees with your
organization's acceptable use and security policies." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:N/I:P/A:N");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N");
 script_set_attribute(attribute:"cvss_score_source", value:"manual");
 script_set_attribute(attribute:"cvss_score_rationale", value:"Score from a more in depth analysis done by Tenable");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/08/08");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"agent", value:"unix");
 script_end_attributes();

 script_summary(english: "Checks that running daemons are registered with RPM / dpkg / emerge");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2008-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english: "Misc.");
 script_require_keys("Host/uname");
 script_dependencies("ssh_get_info.nasl", "process_on_port.nasl");
 exit(0);
}

include('ssh_func.inc');
include('telnet_func.inc');
include('local_detection_nix.inc');

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else
  disable_ssh_wrappers();

var uname = get_kb_item("Host/uname");
if ( ! uname || "Linux" >!< uname ) audit(AUDIT_OS_NOT, "Linux");;

var pkg_system = NULL;

# We cannot solely rely on the fact that the 'rpm' command is installed (it can be
# installed on Debian or Gentoo for instance).
#
# Although there are other RPM based distros, we do not support them to
# avoid FP.
var v = get_kb_list('Host/*/rpm-list');
if (! isnull(v)) pkg_system = "RPM";
else
{
 v = get_kb_list('Host/*/dpkg-l');
 if (! isnull(v)) pkg_system = 'dpkg';
 else
 {
  v = get_kb_item('Host/Gentoo/qpkg-list');
  if (strlen(v) > 0) pkg_system = "emerge";
  else
  {
   audit(AUDIT_OS_NOT, "running rpm, dpkg, or emerge");	# Unsupported distro
  }
 }
}

v = NULL;	# Free memory


var full_path_l = get_kb_list("Host/Daemons/*/*/*");
if (isnull(full_path_l)) exit(0, "No daemons detected running.");
full_path_l = make_list(full_path_l);
if (max_index(full_path_l) == 0) exit(0);

info_connect(exit_on_fail:TRUE);

var prev = NULL;
var bad = "";
var bad_n = 0;
var d, found, buf;
foreach d (sort(full_path_l))
  if (strlen(d) > 0 && d != prev && d[0] == '/' )
  {
    match = pregmatch(pattern:"^(.+) \(deleted\)$", string:d);
    if (match) d = match[1];

    prev = d;
    d = str_replace(find:"'", replace:"'\''", string:d);
    found = ldnix::run_cmd_template_wrapper(template:'LC_ALL=C test -f \'$1$\' && echo FileFound', args:[d]);
    if ('FileFound' >!< found)
    {
      dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:
        'Did not locate file: ' + d);
      continue;
    }

    if (pkg_system == 'RPM')
    {
      buf = ldnix::run_cmd_template_wrapper(template:'LC_ALL=C rpm -q -f \'$1$\' || echo FileIsNotPackaged', args:[d]);
      if ("FileIsNotPackaged" >< buf || strcat("file ", d, " is not by any package") >< buf)
      {
        bad = strcat(bad, d, '\n');
	      bad_n ++;
      }
    }
    else if ( pkg_system == "dpkg" )
    {
      buf = ldnix::run_cmd_template_wrapper(template:'LC_ALL=C dpkg -S \'$1$\' || echo FileIsNotPackaged', args:[d]);
      if ("FileIsNotPackaged" >< buf || strcat("dpkg: ", d, " not found.") >< buf)
      {
        # avoid FP for symlinked systemd
        if ('/usr/lib/systemd/systemd' >< buf)
        {
          dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:
            'Skipping symlinked systemd');
          continue;
        }
        bad = strcat(bad, d, '\n');
	      bad_n ++;
      }
    }
    else if (pkg_system == "emerge")
    {
      buf = ldnix::run_cmd_template_wrapper(template:'LC_ALL=C fgrep -q \'obj $1$ \' /var/db/pkg/*/*/CONTENTS || echo FileIsNotPackaged', args:[d]);
      if ("FileIsNotPackaged" >< buf)
      {
        bad = strcat(bad, d, '\n');
	      bad_n ++;
      }
    }
    else
    {
      if(info_t == INFO_SSH) ssh_close_connection();
      exit(0);
    }
  }

if(info_t == INFO_SSH) ssh_close_connection();

var report;
if (bad_n > 0)
{
  if (bad_n <= 1)
    report = 'The following running daemon is not managed by ';
  else
    report = 'The following running daemons are not managed by ';
  report = strcat(report, pkg_system, ' :\n\n', bad);
  security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : '\n' + report
  );
}
