#TRUSTED 67d45769ce72a0957ba11faebb8a127a271d8a89bfce43064daf52610715bae49a994b54f1f373806960f32bcc0434918c1ffac68303fd5d4c84bbe99e024cf37da7660318632cf0bbd1ae7960a6b27eca3ae1558f9908f2d2f139b9250ebf9c34bdc24fc245d7221f716bd6af3c540cfa1b322817087f3066cb08e7b1e2c7e4fa737af0bcb3fb35b7183c8bafacd30873af5ca8e057d4063534d5d22d18edba194c676ba475c658c959737632e4770f7a4c9ce219d4d818d15c5e217ccb92370e8d5ffd1e9aaa8eabff607addde4adca259fb414ed7fef4c20f2b8eb05b317d9d64415d75e931e1109035f5cfb01d7d2d8f9cd9dec3e9af425ba1f9c36d76c54b58c4afd01e590c50593854df0132656912974034fad3eed78549b366aadaafd63be6a0c48a0c476285ea8567d1a1436d073380a51bae53a182c8b9ad566d0a2fb3a6ffc8b68c49a62d086cc3df6aa28c6ceea82223a1c99b7ddfc02c32ff3544ce25da446abcc6aad1f28cb9cfd5a10d1b68a5688ca357e8b2fb50cafcd9b55412436100fb40e2d1ca6f7f56dc213e92d9731ea93013e2542c1db69faa1ff5c18ab96a0c8507737e131f661ff6001000cdf5b52ed569e59137b7d312fc1aa5b59a06436861f8cd19823d822cdf09f35c36d63dc68cd5ed3066a270269da99db11699930109d24b36f2ce7958b40b25b8f9d72a1ec0856fc9e8eddd0970c45e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89027);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");


  script_name(english:"Tenable SecurityCenter PHP Character Handling (TNS-2015-09)");
  script_summary(english:"Checks the version of PHP in SecurityCenter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote application is affected by a character handling
vulnerability in the bundled version of PHP.");
  script_set_attribute(attribute:"description", value:
"The SecurityCenter application installed on the remote host contains a
bundled version of PHP that is prior to 5.4.43. It is, therefore,
affected by an exclamation mark character handling issue in the
escapeshellcmd() and escapeshellarg() PHP functions. A remote attacker
can exploit this to substitute environment variables.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2015-09");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=69768");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.4.43");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.5.27");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.6.11");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch as referenced in the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:'cvss_score_rationale', value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_keys("Host/SecurityCenter/Version", "installed_sw/SecurityCenter", "Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("install_func.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
sc_ver = get_kb_item("Host/SecurityCenter/Version");
port = 0;
if(empty_or_null(sc_ver))
{
  port = 443;
  install = get_single_install(app_name:"SecurityCenter", combined:TRUE, exit_if_unknown_ver:TRUE);
  sc_ver = install["version"];
}
# Affected: SecurityCenter 4.8, 4.8.1, 5.0.0.1
if (sc_ver !~ "^(4\.8($|\.)|5\.0\.0\.)") audit(AUDIT_INST_VER_NOT_VULN, "SecurityCenter", sc_ver);

# Establish running of local commands
if ( islocalhost() )
{
  if ( ! defined_func("pread") ) audit(AUDIT_NOT_DETECT, "pread");
  info_t = INFO_LOCAL;
}
else
{
  sock_g = ssh_open_connection();
  if (! sock_g) audit(AUDIT_HOST_NOT, "able to connect via the provided SSH credentials.");
  info_t = INFO_SSH;
}

line = info_send_cmd(cmd:"/opt/sc4/support/bin/php -v");
if (empty_or_null(line)) line = info_send_cmd(cmd:"/opt/sc/support/bin/php -v");
if (empty_or_null(line))
{
  if(info_t == INFO_SSH) ssh_close_connection();
  audit(AUDIT_UNKNOWN_APP_VER, "PHP (within SecurityCenter)");
}

if(info_t == INFO_SSH) ssh_close_connection();

pattern = "PHP ([0-9.]+) ";
match = pregmatch(pattern:pattern, string:line);
if (isnull(match)) audit(AUDIT_UNKNOWN_APP_VER, "PHP (within SecurityCenter)");
version = match[1];

if (version =~ "^5\.4\.") fix = "5.4.43";
else if (version =~ "^5\.5\.") fix = "5.5.27";
else if (version =~ "^5\.6\.") fix = "5.6.11";
else fix = "5.4.43"; # default to known php release branch used in advisory

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report = '\n' +
    '\n  SecurityCenter version     : ' + sc_ver +
    '\n  SecurityCenter PHP version : ' + version +
    '\n  Fixed PHP version          : ' + fix +
    '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "PHP (within SecurityCenter)", version);
