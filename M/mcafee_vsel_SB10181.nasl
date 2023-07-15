#TRUSTED 366281f5163c6f2e3ae4cb5af1016a4fa6a45bb2e89806a9b9662d9b3041c3327fb4e476a3b54e6cb6571179232d3498c9ec10a7e919e6d46538652f2eabbb595c5bf82ad3a0c9ff48d38765e7fb65e0992d1262bc155263bc1a29885cb8910168eb44d963a067b8f385d6b70bc92b6c4bfabb3758ea74c86725da1499c2dbaafe16c6a590db272c55fb37ed377557eecc432fdeeb9d7da0112ed1132007634c7f19f6ab9f6019e14167a6677b27b7afdcf4d144c3182ffcacf0879b7a1c77227f7e22ed576edd266edbbdb42b490bcce94a172437d65b2e0fe255aa7f6aa7c6be6a5f11f2b9150974219862264a4c7a55956b51b107c92f87b3601b2a825ec7c634206ba6b70cfb2274f75a26e93d4ea4596a6c5db95f5575be8a6cf3d240c24b6b6feadbe1eb4dfd0b0048b26dbfa7cfa6b99d8c0acda273b0d9d7e285fcec50fb9fce8c33248307bc352ddb32a826c9fe3163326479d9f31488af9d12830c86a92be35ff50a6bda3075223a339f4278453bcc121fbbd30412492517198629ab9cbc6bfa2ee5dcfd5b223269a3a5a6c4e3791f9262ded98a424c8a922c457491895d357a4937909b62dfed181ffa8e5711d319d2cc36746193eb74eac65b8a04f3763d4c682824a2bc313cea06f2560f4731dbd5270f73540d6a66e1c378ac61082ba638ed013d3b6ecbc404014c42bf18847fa43e6280a9542af72c22f175
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(95812);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2016-8016",
    "CVE-2016-8017",
    "CVE-2016-8018",
    "CVE-2016-8019",
    "CVE-2016-8020",
    "CVE-2016-8021",
    "CVE-2016-8022",
    "CVE-2016-8023",
    "CVE-2016-8024",
    "CVE-2016-8025"
  );
  script_bugtraq_id(94823);
  script_xref(name:"MCAFEE-SB", value:"SB10181");
  script_xref(name:"CERT", value:"245327");
  script_xref(name:"EDB-ID", value:"40911");

  script_name(english:"McAfee VirusScan Enterprise for Linux <= 2.0.3 Multiple vulnerabilities (SB10181)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of McAfee VirusScan Enterprise for Linux
(VSEL) installed that is prior or equal to 2.0.3. It is, therefore,
affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists in the
    web interface due to improper error reporting. An
    authenticated, remote attacker can exploit this, by
    manipulating the 'tplt' parameter, to disclose filenames
    on the system. (CVE-2016-8016)

  - An information disclosure vulnerability exists in the
    parser due to improper handling of template files. An
    authenticated, remote attacker can exploit this, via
    specially crafted text elements, to disclose the
    contents of arbitrary files subject to the privileges of
    the 'nails' account. (CVE-2016-8017)

  - Multiple cross-site request forgery (XSRF)
    vulnerabilities exist in the web interface due to a
    failure to require multiple steps, explicit
    confirmation, or a unique token when performing certain
    sensitive actions. An unauthenticated, remote attacker
    can exploit these vulnerabilities, by convincing a user
    to follow a specially crafted link, to execute arbitrary
    script code or commands in a user's browser session.
    (CVE-2016-8018)

  - Multiple cross-site scripting (XSS) vulnerabilities
    exist due to improper validation of user-supplied input
    to the 'info:7' and 'info:5' parameters when the 'tplt'
    parameter is set in NailsConfig.html or
    MonitorHost.html. An unauthenticated, remote attacker
    can exploit these vulnerabilities, via a specially
    crafted request, to execute arbitrary script code in a
    user's browser session. (CVE-2016-8019)

  - A remote code execution vulnerability exists due to
    improper validation of user-supplied input to the
    'nailsd.profile.ODS_9.scannerPath' variable in the last
    page of the system scan form. An authenticated, remote
    attacker can exploit this, via a specially crafted HTTP
    request, to execute arbitrary code as the root user.
    (CVE-2016-8020)

  - A remote code execution vulnerability exists in the web
    interface when downloading update files from a specified
    update server due to a race condition. An authenticated,
    remote attacker can exploit this to place and execute a
    downloaded file before integrity checks are completed.
    (CVE-2016-8021)

  - A security bypass vulnerability exists in the web
    interface due to improper handling of authentication
    cookies. The authentication cookie stores the IP address 
    of the client and is checked to ensure it matches the
    IP address of the client sending it; however, an 
    unauthenticated, remote attacker can cause the cookie to
    be incorrectly parsed by adding a number of spaces to
    the IP address stored within the cookie, resulting in a
    bypass of the security mechanism. (CVE-2016-8022)

  - A security bypass vulnerability exists in the web
    interface due to improper handling of the nailsSessionId
    authentication cookie. An unauthenticated, remote
    attacker can exploit this, by brute-force guessing the
    server start authentication token within the cookie, to
    bypass authentication mechanisms. (CVE-2016-8023)

  - An HTTP response splitting vulnerability exists due to
    improper sanitization of carriage return and line feed
    (CRLF) character sequences passed to the 'info:0'
    parameter before being included in HTTP responses. An
    authenticated, remote attacker can exploit this to
    inject additional headers in responses and disclose
    sensitive information. (CVE-2016-8024)

  - A SQL injection (SQLi) vulnerability exists in the web
    interface due to improper sanitization of user-supplied
    input to the 'mon:0' parameter. An authenticated, remote
    attacker can exploit this to inject or manipulate SQL
    queries in the back-end database, resulting in the
    manipulation or disclosure of arbitrary data.
    (CVE-2016-8025)");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10181");
  script_set_attribute(attribute:"see_also", value:"https://nation.state.actor/mcafee.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Endpoint Security for Linux (ENSL) version 10.2.0 or later.
Alternatively, as a workaround, open the following line in a text editor:
'/var/opt/NAI/LinuxShield/etc/nailsd.cfg' and change 'nailsd.disableCltWEbUI: false' 
to the value of true and restart the nails service.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-8024");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:virusscan_enterprise");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_vsel_detect.nbin");
  script_require_keys("installed_sw/McAfee VirusScan Enterprise for Linux");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");

if ( islocalhost() )
{
  port = 0;
  if ( ! defined_func("pread") ) exit(1, "'pread()' is not defined.");
    info_t = INFO_LOCAL;
}
else
{
  port = kb_ssh_transport();
  if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

  ret = ssh_open_connection();
  if (!ret) audit(AUDIT_FN_FAIL, "ssh_open_connection()");

    info_t = INFO_SSH;
}

app_name = "McAfee VirusScan Enterprise for Linux";
get_install_count(app_name:app_name, exit_if_zero:TRUE);

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
vuln = FALSE;

if (ver_compare(ver:version, fix:"2.0.3", strict:FALSE) <= 0 || version =~ "^2\.0\.3") 
{
  cmd = 'grep nailsd.disableCltWebUI /var/opt/NAI/LinuxShield/etc/nailsd.cfg | tr -d "\n"';
  buf = info_send_cmd(cmd:cmd);
  # match = is temporary workaround in place?
  match = pregmatch(pattern:'nailsd.disableCltWebUI: true', string:buf);
  if (!isnull(match)) audit(AUDIT_HOST_NOT, "affected because 'nailsd.disableCltWebUI' is set to true");
  # set to false & vulnerable
  notSet = pregmatch(pattern:'nailsd.disableCltWebUI: false', string:buf);
  # no config setting & vuln
  dne = pregmatch(pattern:'nailsd.disableCltWebUI:', string:buf);
  # if false or if the config does not exist and we are v2.0.3 then flag as vuln
  if (!isnull(notSet) || isnull(dne)) vuln = TRUE;
}


if (vuln)
{
  port = 0;
  report ='\nInstalled version : ' + version +
          '\nSolution          : Upgrade to McAfee Endpoint Security for Linux (ENSL) 10.2.0 or later.\n';
  security_report_v4(severity:SECURITY_WARNING, extra:report, port:port, xss:TRUE, sqli:TRUE, xsrf:TRUE);
}
else audit(AUDIT_INST_VER_NOT_VULN, version);
