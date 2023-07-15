#TRUSTED 60573b87a28e3fb79252106ae03c72700bc70ed1a1434eab95bf1a625a8b7c8c52d22aaf2744fdee1019dc95d39bdf37c188c71407a3ee8637ee77bd399b99e5db97cd369699e0d8a7e13ac4b4ab06ab4f9cf52f218ea79da93ad9899f54ab41ae0dfe511018e86e3ee1997baa8922ef5ce1931455084d6ea1fb352f1175fb4003f7aa071b7efa52df0e2eae749788fa5c8eb8570431b40d0ba998b2d3b7a52fe6de3acbdf480e484c232d16de0186d0cb5e3b1cbaf335913ac79d2f5831748e860c2030e98c470a9f76a3cc7295837fce3435d52a21a8d25b8dfd8caf33654c24602820f020fd267f5651bbb9308e7ec6f671f037c7719a25a21e87cc2a75b496ad0ddc107159dadfde354a3be58f4262ad8cb73406f473676be152d5d63318502c85a368317011d781016395bfd13b3b459be01405665c970d0a0c07666d8c4aa9064023dfc52f86be3dd022f044cdc60cbdefd4c14f6554fc0aed6989199d5dcb8dab1b20c0a017c6cfea14b6dab5f34b1eb6b697b51b9616a7189d787ffc88cc8a5f86bc90dfca802243012f926a302812d5b15788e5ea99836cf1bb0ca5f3e2bbd7c0b209588828b2191a2177149f089b1aef091de0d7b87b7c9f028d25cc6faa8bc147be6df52339fa631158972e9b9c22119e9123f8c5e3873159006ee12f1087831552d7a8b828ecfbea2d5dc54c2ec7ac85647d502f8189e727d374
#TRUST-RSA-SHA256 0c09f1d5691eb7157c4d6531a68b1d96c2630ad2b93ac43b9969a835849b132236b77116104489ce29d522d1d3212ee35317046290e5e3172f48e82955a46113f706cf4e554fbd429e31b03742ec1c7038c8379c5b47b6ed2f6e123ec557d956a3445244a9ad3a7de733b036152b4906abb9c9e02648290f61b11721010a3c7136b23c437abd1b764d98c6b7e011eace5ea5a06219f59b6fd6f2eb0849e96e6f15a5f6f6cde28654572b93a001140996934f2f68de856394d0d67964a9bd0242b877fde8bc7514418b90d3ab4ea57a3d8e512bbc42537b11e237e9f6dcf309985e0206f3e9c1b482aee23e75a2d8e7965b1a3015df597565159691b9f5412afb52aca7b39b27e5b16a90bf6c16a152073f88706865f107328640a85bedcf1df33ecf4ec7cebbfe7bb2cf2840be807ae3833d9ae567f51f0d901983589f126b5a4a9602f60a645b8206a8f9190459990c6622ec5038b29edfd9a23b6c0fd810be7f6072accc7c3dc3c58aa6aa53ab81f7431b2bdf72d131e92b61ac303a513f17aac6799d39ac9b1ae88a6576c01e952e81d0a6497aad403106f910dd5243ce1165e17c1c65a78553cfbac58b2d32f06b5392e6982299aa58b2d0d67c4663b57d0899aa4c608cc6d44d7b111f7048ce3db05c9cda38db3bc1907d54cc9af650a709b4088c90956a79b31454d9e4b0642d94d0c23f4694f6bcf50669e9a558bd52
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(163103);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/01");


  script_name(english:"System Restart Required");

  script_set_attribute(attribute:"synopsis", value:
  "The remote system has updates installed which require a reboot.");
  script_set_attribute(attribute:"description", value:
"Using the supplied credentials, Nessus was able to determine that the remote system has updates applied that require
a reboot to take effect. Nessus has determined that the system has not been rebooted since these updates have been
applied, and thus should be rebooted.");
  # https://access.redhat.com/solutions/27943
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e9ce1c1");
  # https://www.debian.org/doc/debian-policy/ch-opersys.html#signaling-that-a-reboot-is-required
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd8caec2");
  script_set_attribute(attribute:"solution", value:"Restart the target system to ensure the updates are applied.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Linux");

  exit(0);
}

include('rpm.inc');
include('debian_package.inc');
include('ubuntu.inc');
include("ssh_func.inc");
include("hostlevel_funcs.inc");
include("datetime.inc");
include('local_detection_nix.inc');

# Check whether the package install date is more recent than the uptime
# today - uptime gives us the last boot date
# if last boot date is less than the rpm_install_time, 
# the package was installed after the last boot
function pkg_installed_after_last_boot(uptime, today, rpm_install_time)
{
  if (empty_or_null(uptime) || empty_or_null(today) || empty_or_null(rpm_install_time))
    audit(AUDIT_HOST_NOT, "providing valid date information.");

  var last_boot = today - uptime;
  dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'comparing pkg time with last boot: uptime: '+uptime+', today: '+today+', rpm_install_time: '+rpm_install_time+', last_boot: '+last_boot+'\n');

  if ( last_boot < rpm_install_time )
    return TRUE;
  return FALSE;
}

function restart_required_zypper()
{
  var report = '';
  var reboot_needed_path = '/run/reboot-needed';
  if (ldnix::file_exists(file:reboot_needed_path))
  {
    dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'reboot_needed file exists\n');
    report += 'The reboot needed flag is set at :\n\n';
    report += reboot_needed_path + '\n\n';
  }

  return report;
}


function restart_required_apt()
{
  var reboot_required, reboot_required_pkgs;
  var report = '';
  var reboot_required_paths = [
    {'rr':'/run/reboot-required',     
     'pkgs':'/run/reboot-required.pkgs'},
    {'rr':'/var/run/reboot-required', 
     'pkgs':'/var/run/reboot-required.pkgs'}
  ];

  foreach var path (reboot_required_paths)
  {
    reboot_required = chomp(ldnix::get_file_contents(file:path['rr']));
    reboot_required_pkgs = chomp(ldnix::get_file_contents(file:path['pkgs']));
    if ( empty_or_null(reboot_required) && empty_or_null(reboot_required_pkgs) )
      continue;

    dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'reboot_required: '+reboot_required+', reboot_required_pkgs: '+reboot_required_pkgs+'\n');

    if (!empty_or_null(reboot_required))
    {
      report += 'The reboot required flag is set :\n\n';
      report += reboot_required + '\n\n';
    }

    if ( !empty_or_null(reboot_required) )
    {
      report += 'The following packages require a reboot :\n\n';
      report += reboot_required_pkgs + '\n\n';
    }
    break;
  }
  return report;
}

function restart_required_rpm()
{
  # for each rpm in [['kernel', 'glibc', 'linux-firmware', 'systemd', 'udev',
  #            'openssl-libs', 'gnutls', 'dbus']
  # if float(pkg.installtime) > float(boot_time) 
  #     reboot required
  # see https://access.redhat.com/solutions/27943
 
  var rpm_install_time, match, pattern, rpm_name, report;
  var rpm_list_date = get_kb_list('Host/*/rpm-list-date');
  var rebootpkgs = ['kernel', 'glibc', 'linux-firmware', 'systemd', 'udev', 'openssl-libs', 'gnutls', 'dbus'];
  var today_cmd = 'date \'+%s\'';
  var uptime_file = '/proc/uptime';
  var date_format_pattern = "^\w{3}\s+\w{3}\s+\d{2}\s+\d{2}\:\d{2}\:\d{2}\s+\d{4}$";
  var today = int(chomp(info_send_cmd(cmd:today_cmd)));
  var uptime = ldnix::get_file_contents(file:uptime_file);

  if ( empty_or_null(uptime) || empty_or_null(today) )
    return '';

  uptime = split(uptime, sep:' ');
  uptime = int(uptime[0]);

  dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'today: '+today+', uptime: '+uptime+'\n');

  if ( uptime == 0 || today == 0 )
    audit(AUDIT_HOST_NOT, "providing valid date information.");

  if(!empty_or_null(rpm_list_date))
  {
    # split rpm-list on \n
    foreach var key (list_uniq(keys(rpm_list_date)))
    {
      foreach var rpm (split(rpm_list_date[key], sep:'\n', keep:TRUE))
      {
        foreach var pkg (rebootpkgs)
        {
          pattern = "^"+pkg+"-[^-]+-[^\|-]+\|\S+\s+(.*)$";
          match = pregmatch(pattern:pattern, string:rpm);
          if ( match && match[1] )
          {
            # Sanity check the date format even though it is enforced by Nessus
            if(pregmatch(pattern:date_format_pattern, string:match[1]))
              rpm_install_time = logtime_to_unixtime(timestr:match[1]);
            else
            {
              dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'unreadable date format for rpm entry: ' + rpm);
              continue;
            }

            dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'checking pkg: '+pkg+', on host with uptime: '+uptime+', today: '+today+', and rpm_install_time: '+rpm_install_time+'\n');
            if ( rpm_install_time == 0 )
              continue;

            if ( pkg_installed_after_last_boot(uptime:uptime, today:today, rpm_install_time:rpm_install_time) )
            {
              # Showing only the package name, version, release and epoch in the report
              rpm_name = rpm - '      ' - match[1];
              report += '    ' + rpm_name + '\n';
            }
          }
        }
      }
    }
  }
  return report;
}

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var uname=get_kb_item("Host/uname");
if(empty_or_null(uname)) audit(AUDIT_KB_MISSING, "Host/uname");
else if("Linux" >!< uname) audit(AUDIT_OS_NOT, "Linux");

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS)
  enable_ssh_wrappers();
else disable_ssh_wrappers();

info_connect(exit_on_fail:TRUE);

var report, report_flag = "";
var debian, rhel;

if ( !empty_or_null(get_kb_list('Host/*/rpm-list')) )
{
  report = restart_required_rpm();
  
  if ( get_kb_item("Host/SuSE/release") )
  {
    report_flag = restart_required_zypper();
  }
}
# Ubuntu OS populates the Host/Debian/dpkg-l KB list
else if ( !empty_or_null(get_kb_list('Host/*/dpkg-l')) )
{
  report = restart_required_apt();
}
else
{
  if (info_t == INFO_SSH) ssh_close_connection();
  audit(AUDIT_HOST_NOT, 'supported by this check.');
}
if (info_t == INFO_SSH) ssh_close_connection();

dbg::detailed_log(lvl:2, src:SCRIPT_NAME, msg:'got report info: '+report+'\n');

if (!empty_or_null(report) || !empty_or_null(report_flag))
{
  if (!empty_or_null(object:report))
    report = 'The following security patches require a reboot but have been installed since the most recent system boot: \n\n' + report + '\n\n';
  if (!empty_or_null(object:report_flag))
    report += report_flag;
  security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);
}
else
  audit(AUDIT_HOST_NOT, 'affected');