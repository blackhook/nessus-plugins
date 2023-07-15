#TRUSTED 58b97857fdae7879f65d1b1876d8c6d67d811f88119a3ed6f71f580f97cf675384f1d386787462f964ae77f4beab268b1ab99ecb0450a2b3baa5c3415183f98274552ac410bf7b560346df0fd4e3c31a1afd523a1f7d179b319f1e1ce319308b1fbab46d7a33b109fffcd03156047c41892a7817055bf7edac53d56c842874011b74483dbb7ebcf435deafade80ade844bdc4b892c39889380d78a02e67837b50153113c1905806e40d1b2bd43f77c34dfa1923c54cf8676ca1d234a8c7eb98eb1b61b577acf57315c3472140d9dbf66418fbb8da83143688b696639780c54f11ed671dc0e89e8e70a397c85f79a4938c48d74c1e5947f6011259b47a555c92dba9e15245f7d19061129e2ea7c5728786aecef329b1f288533a7ca99000c979ae19d572e725c818f4696b66ea45d43f78df884cecc30071712e9ee2754c15084fead5283cdb1c2fe3ea74057db1523cdbace5a71971a0a8eb0bd6f67b971fef98602db4a37471abb5fae6ce501ad35d5250474b8715e67229d44b772168b88a1fc6bf910328bfc76bd5ff050cf4794359364448168e705d8ebc773a0bd60a0d48b28135996adf1922b42e8ff7bb7e8942c7bb4fbbd2ba2dbf585ffe08ce563916ebc78cba645374ff1a1d457b66c7fb85877f6a75f7acb118f1eef29cf364f9a92f921d0f4442b119a3df80643914cd0e1b0aa9858c13be3a289b6d146030d7e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85628);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2015-3183", "CVE-2015-3185");
  script_bugtraq_id(75963, 75965);

  script_name(english:"Tenable SecurityCenter Multiple Apache Vulnerabilities (TNS-2015-11)");
  script_summary(english:"Checks the version of Apache in SecurityCenter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote application is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Tenable SecurityCenter application installed on the remote host
contains a bundled version of Apache HTTP Server prior to 2.4.16. It
is, therefore, affected by the following vulnerabilities :

  - A flaw exists in the chunked transfer coding
    implementation in http_filters.c. due to a failure to
    properly parse chunk headers when handling large
    chunk-size values and invalid chunk-extension
    characters. A remote attacker can exploit this, via a
    crafted request, to carry out HTTP request smuggling,
    potentially resulting in cache poisoning or the
    hijacking of credentials. (CVE-2015-3183)

  - A security bypass vulnerability exists due to a failure
    in the ap_some_auth_required() function in request.c to
    consider that a Require directive may be associated with
    an authorization setting instead of an authentication
    setting. A remote attacker can exploit this, by
    leveraging the presence of a module that relies on the
    2.2 API behavior, to bypass intended access restrictions
    under certain circumstances.
    (CVE-2015-3185)

Note that the 4.x version of SecurityCenter is impacted only by
CVE-2015-3183. The 5.x version is impacted by both CVE-2015-3183 and
CVE-2015-3185");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2015-11");
  script_set_attribute(attribute:"see_also", value:"http://www.apache.org/dist/httpd/Announcement2.2.html");
  script_set_attribute(attribute:"see_also", value:"http://www.apache.org/dist/httpd/Announcement2.4.html");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch for version 4.7.1 / 4.8.2 as referenced in
the vendor advisory. Alternatively, upgrade to Tenable SecurityCenter
version 5.0.2.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-3183");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

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

if (! get_kb_item("Host/local_checks_enabled"))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

sc_ver = get_kb_item("Host/SecurityCenter/Version");

port = 0;
if(empty_or_null(sc_ver))
{
  port = 443;
  install = get_single_install(app_name:"SecurityCenter", combined:TRUE, exit_if_unknown_ver:TRUE);
  sc_ver = install["version"];
}
# No patches for SC 4.6
if (! preg(pattern:"^(4\.[678]|5)\.", string:sc_ver))
  audit(AUDIT_INST_VER_NOT_VULN, "SecurityCenter", sc_ver);

# Depending on the version of SC, the path and fix differ.
sc_path = "";
fix = "";

if (sc_ver =~ "^4\.")
{
  fix = "2.2.31";
  sc_path = "sc4";
}
else if (sc_ver =~ "^5\.")
{
  fix = "2.4.16";
  sc_path = "sc";
}

# Establish running of local commands
if (islocalhost())
{
  if (! defined_func("pread"))
    audit(AUDIT_NOT_DETECT, "pread");
  info_t = INFO_LOCAL;
}
else
{
  sock_g = ssh_open_connection();
  if (! sock_g)
    audit(AUDIT_HOST_NOT, "able to connect via the provided SSH credentials.");
  info_t = INFO_SSH;
}

line = info_send_cmd(cmd:"/opt/" + sc_path + "/support/bin/httpd -v");
if (info_t == INFO_SSH) ssh_close_connection();

if (!line)
  audit(AUDIT_UNKNOWN_APP_VER, "Apache (bundled with SecurityCenter)");

pattern = "Server version: Apache/([0-9.]+) ";
match = pregmatch(pattern:pattern, string:line);

if (isnull(match))
  audit(AUDIT_UNKNOWN_APP_VER, "Apache (bundled with SecurityCenter)");

version = match[1];

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report = '\n' +
    '\n  SecurityCenter version        : ' + sc_ver +
    '\n  SecurityCenter Apache version : ' + version +
    '\n  Fixed Apache version          : ' + fix +
    '\n';
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Apache (bundled with SecurityCenter)", version);
