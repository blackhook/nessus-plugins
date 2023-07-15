#TRUSTED 00f3b1fda242644862d3dd8bf4db924d7ebe0f136971c4313c9a0785fee8701c7672972acf06853e2fbbabc62e0e6c4a1dda632e788d67e5b0a8d92b2f40a30541cad5bb49f1d486d0169537629330895d3f51484627d612f52b638ba9aab1eb6f13f8d55c2bff76c60abeab6a8637a44c8d24763806a4391cd5e1698a67102d8a5bb4e1d02fbf80f548fb8da1374593c8760c15db05f20eb8e569ee09f867e1575756d01d36bea64e0790eb1039c7c3d6b8c053af1911af4efe457252b2d1a23cbd82e9054f3bc63176a201614e3707214e78bf282fdfa250fbcae1e73c98efe49b0c06d6c78f5a4494ecb4d5cd1da63c55f1e3790bbddd0840ec1aa211f863e8c1b3a1ef79ebf6aa0ed8fd141c6c61d83394e71792415f943d4a7230a12e6438deeed2950131e1fb6ac29818cb6546428db83a6b72d0b7d705ab33ac1a1e6646722158b1c1f2253d501a350acb889583dfcb91aa1dc335b4f8eafea2e588c881c8025b38e6e4e9ff529ba855d37b4704f65c47a0e8ccb4c8b9c2ae65b10f825667ec45c6d7dfd120374b5b836f64dd8607715021e03d0a040697d11bc3ec4c439ac70434f1bc954bc2fe35e5696806fd3c11b4fb70378b49e82bae6d8c47939321ecb875565db005bb7e9832a1b0a8ff841359bd9d287d86afe2da3268e57ca7bd6051e3133aaf4f2cc5a487c98bcdce146d2cb603eabcf490b05badeccada
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85566);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id(
    "CVE-2006-7243",
    "CVE-2015-2325",
    "CVE-2015-2326",
    "CVE-2015-4021",
    "CVE-2015-4022",
    "CVE-2015-4024",
    "CVE-2015-4025",
    "CVE-2015-4026"
  );
  script_bugtraq_id(
    44951,
    74700,
    74902,
    74903,
    74904,
    75056,
    75174,
    75175
  );

  script_name(english:"Tenable SecurityCenter Multiple PHP Vulnerabilities (TNS-2015-06)");
  script_summary(english:"Checks the version of PHP in SecurityCenter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote application is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The SecurityCenter application installed on the remote host is
affected by multiple vulnerabilities in the bundled version of PHP
that is prior to version 5.4.41. It is, therefore, affected by the
following vulnerabilities :

 - A flaw in the phar_parse_tarfile function in
    ext/phar/tar.c could allow a denial of service
    via a crafted entry in a tar archive.
    (CVE-2015-4021)

  - An integer overflow condition exists in the
    ftp_genlist() function in ftp.c due to improper
    validation of user-supplied input. A remote attacker can
    exploit this to cause a heap-based buffer overflow,
    resulting in a denial of service condition or possible
    remote code execution. (CVE-2015-4022)

  - Multiple flaws exist related to using pathnames
    containing NULL bytes. A remote attacker can exploit
    these flaws, by combining the '\0' character with a safe
    file extension, to bypass access restrictions. This had
    been previously fixed but was reintroduced by a
    regression in versions 5.4+. (CVE-2006-7243,
    CVE-2015-4025)

  - Multiple heap buffer overflow conditions exist in the
    bundled Perl-Compatible Regular Expression (PCRE)
    library due to improper validation of user-supplied
    input to the compile_branch() and pcre_compile2()
    functions. A remote attacker can exploit these
    conditions to cause a heap-based buffer overflow,
    resulting in a denial of service condition or the
    execution of arbitrary code. (CVE-2015-2325,
    CVE-2015-2326)

  - A security bypass vulnerability exists due to a flaw in
    the pcntl_exec implementation that truncates a pathname
    upon encountering the '\x00' character. A remote
    attacker can exploit this, via a crafted first argument,
    to bypass intended extension restrictions and execute
    arbitrary files. (CVE-2015-4026)

  - A flaw exists in the multipart_buffer_headers() function
    in rfc1867.c due to improper handling of
    multipart/form-data in HTTP requests. A remote attacker
    can exploit this flaw to cause a consumption of CPU
    resources, resulting in a denial of service condition.
    (CVE-2015-4024)");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2015-06");
  script_set_attribute(attribute:"see_also", value:"https://secure.php.net/ChangeLog-5.php#5.4.41");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-4026");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(4\.[6789]|5)\.", string:sc_ver)) audit(AUDIT_INST_VER_NOT_VULN, "SecurityCenter", sc_ver);

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
if (!line) line = info_send_cmd(cmd:"/opt/sc/support/bin/php -v");
if (!line)
{
  if(info_t == INFO_SSH) ssh_close_connection();
  audit(AUDIT_UNKNOWN_APP_VER, "PHP (within SecurityCenter)");
}

if(info_t == INFO_SSH) ssh_close_connection();

pattern = "PHP ([0-9.]+) ";
match =pregmatch(pattern:pattern, string:line);
if (isnull(match))
  audit(AUDIT_UNKNOWN_APP_VER, "PHP (within SecurityCenter)");

version = match[1];

if (version =~ "^5\.4\.") fix = "5.4.41";
else if (version =~ "^5\.5\.") fix = "5.5.25";
else if (version =~ "^5\.6\.") fix = "5.6.9";
else fix = "5.4.41"; # default to known php release branch used in advisory

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
