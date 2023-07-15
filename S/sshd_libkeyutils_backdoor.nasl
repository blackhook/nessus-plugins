#TRUSTED 5d17d63692d89011a440f5578e900a18b4f9b13373dc12ef7aeb83a0c4c8974adc1926b5f91558c08336143a66034edca0d58d34e079cb09da9d232bd41604528c96907959a9049d080b5ae897df0f7919f0d5bd9678ec7f20d0f805e386e87f77c5f6401ed56d5f1c9d7d734104e293bf48a0eefb1661e6db6b6b2d964ae78ac900ba1b7329557c43e4734cb7ad44d8b68c1b0f1e05518f0ca7f93984122ae2b249a9a847d4b0dcee25821097b0a427fa31f73e81c24d596daa67f0d0e1092ef112af9016a3136cfefacf48c78efef663c9eeb9da36b9b817d4bb30ad29bfa620504506f539140d9afa8d4efc2f29ac464ab0a16a7673758a34161788fd32dd0f67cb46ac262307bd7a9b8ac28c88ac60eb570f6089e44c47d72afc2cb89f773bad99c8b45b33a7a8fc7f1ac91ed9904aaafb0506d238d5a027c658051ea672015f0334382d77e53530ff90b77aac03ef2286b090b27a83bd10f0ac521e51473fca96a7c653c1c0954149c8ab1b665ad2c7adb71f6c9c56e9065932774d529e55cf8fcb6dc85f3d691f2a9acd81c5a88d3437c3ea760e5d34e1558ad65b9788ec6da2d063582fa3fd565b3ba8f272106263ed600cb0e27999314e532ccf99e0f7307c4784eb0317ce5a0b11f8ea3d95a358eb82a5a270398bf6273615095c9da310620377c8c0745ef7ad4dc9d00f5a62e30becf67f85d38a96e58a8ca10867
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64913);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_name(english:"SSHD libkeyutils Backdoor");
  script_summary(english:"Checks for evidence of a libkeyutils library being trojaned");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host may be compromised."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host appears to contain a trojaned libkeyutils library.  The
trojaned library links to SSHD, steals credentials, and sends spam."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.webhostingtalk.com/showthread.php?t=1235797");
  # http://blog.solidshellsecurity.com/2013/02/18/0day-linuxcentos-sshd-spam-exploit-libkeyutils-so-1-9/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f62cb60d");
  # http://contagiodump.blogspot.com/2013/02/linuxcentos-sshd-spam-exploit.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b03816df");
  # https://isc.sans.edu/diary/SSHD%20rootkit%20in%20the%20wild/15229
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4958f5dd");
  script_set_attribute(attribute:"see_also", value:"http://www.webhostingtalk.com/showpost.php?p=8563741&postcount=284");
  script_set_attribute(
    attribute:"solution",
    value:
"Verify whether or not the system has been compromised.  Restore from
known good backups and investigate the network for further signs of a
compromise, if necessary."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2013-2022 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("telnet_func.inc");
include("ssh_func.inc");
include("hostlevel_funcs.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled"))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

# public reports indicate only RPM-based distros have been infected
rpm_list = get_kb_list_or_exit('Host/*/rpm-list');
rpm_list = make_list(rpm_list);
rpm_list = split(rpm_list[0], sep:'\n', keep:FALSE);

keyutils_rpms = make_list();

foreach line (rpm_list)
{
  fields = split(line, sep:'|', keep:FALSE);
  rpm = fields[0];
  if (rpm =~ "^keyutils-libs-\d")
    keyutils_rpms = make_list(keyutils_rpms, rpm);
}

if (max_index(keyutils_rpms) == 0)
  audit(AUDIT_NOT_INST, 'keyutils-libs');

# initialization required for using info_send_cmd()
if (islocalhost())
{
  if (!defined_func("pread")) audit(AUDIT_FN_UNDEF, 'pread');
  info_t = INFO_LOCAL;
}
else
{
  sock_g = ssh_open_connection();
  if (!sock_g) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
  info_t = INFO_SSH;
}

affected_files = make_array();
rpm_verify = make_array();

foreach rpm (keyutils_rpms)
{
  # verify the files in the rpm package
  rpm_cmd = '/bin/rpm -Vv ' + rpm;
  rpm_output = info_send_cmd(cmd:rpm_cmd);
  output_lines = split(rpm_output, sep:'\n', keep:FALSE);

  foreach line (output_lines)
  {
    # determine if the size and md5sum of any library files have changed
    match = eregmatch(string:line, pattern:"^S.5......\s+(/lib(64)?/libkeyutils.+)$");
    file = match[1];
    if (isnull(file)) continue;

    # if so, check if the file contains the encoded IP address associated with this backdoor.
    # the string below is 78.47.139.110 - each byte is xor'd with 0x81
    encoded_ip = "\xb6\xb9\xaf\xb5\xb6\xaf\xb0\xb2\xb8\xaf\xb0\xb0\xb1";
    cmd = "/bin/grep -P '" + encoded_ip + "' " + file + ' &> /dev/null ; /bin/echo $?';
    results = info_send_cmd(cmd:cmd);

    if (chomp(results) == '0') # avoid false negatives by checking the exit status
    {
      affected_files[file] = cmd;
      rpm_verify[rpm_cmd] = rpm_output;
    }
  }
}

ssh_close_connection();

if (max_index(keys(affected_files)) == 0)
  audit(AUDIT_HOST_NOT, 'affected');

if (report_verbosity > 0)
{
  if (max_index(keys(affected_files)) == 1)
    s = ' appears';
  else
    s = 's appear';

  report =
    '\nThe following file' + s + ' to contain backdoor code :\n\n' +
    join(sort(keys(affected_files)), sep:'\n') +'\n\n' +
    'This was determined by verifying any libkeyutils RPM packages :\n\n' +
    join(sort(keys(rpm_verify)), sep:'\n') + '\n\n' +
    join(sort(make_list(rpm_output)), sep:'\n') + '\n' +
    'And checking if any modified library files contain a string which\n' +
    'can be decoded to "78.47.139.110" (an IP address associated with the\n' +
    'backdoor) :\n\n';
  foreach key (sort(keys(affected_files)))
    report += affected_files[key] + '\n';

  security_hole(port:0, extra:report);
}
else security_hole(0);
