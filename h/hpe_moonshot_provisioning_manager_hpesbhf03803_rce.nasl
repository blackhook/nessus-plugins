#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106460);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2017-8975", "CVE-2017-8976");
  script_bugtraq_id(102410);
  script_xref(name:"ZDI", value:"ZDI-18-001");
  script_xref(name:"ZDI", value:"ZDI-18-002");
  script_xref(name:"HP", value:"HPESBHF03803");

  script_name(english:"HPE Moonshot Provisioning Manager < 1.22 Multiple Vulnerabilities");
  script_summary(english:"Detects if the fix has been applied.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The HPE Moonshot Provisioning Manager running on the remote host is
affected by two remote code execution vulnerabilities in the
khuploadfile.cgi file due to the lack of proper validation of
user-supplied data. An unauthenticated, remote attacker can exploit
these issues, via a specially crafted HTTP POST message, to upload
arbitrary files which could allow the attacker to execute arbitrary
code.

Note that the product is reportedly affected by an additional
vulnerability in the server_response.py file; however, this plugin
has not tested for it.");
  # https://support.hpe.com/hpsc/doc/public/display?docId=hpesbhf03803en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14d657df");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-18-001/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-18-002/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HPE Moonshot Provisioning Manager v1.22 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8976");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:hpe:moonshot_provisioning_manager");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hpe_moonshot_provisioning_manager_detect.nbin");
  script_require_keys("installed_sw/HPE Moonshot Provisioning Manager");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "HPE Moonshot Provisioning Manager";

# Exit if MPM is not detected on the target
get_install_count(app_name:app, exit_if_zero:TRUE);

# Exit if MPM is not detected on this port 
port = get_http_port(default:443);
install = get_single_install(app_name:app, port:port);

#
# Request 1: Get the upload directory
#
url = '/cgi-bin/khuploadfile.cgi';

filename = crap(data:'A', length:300);
data = 'isofile.savepath=.&isofile.filename=' + filename;
res = http_send_recv3(
  method        : 'POST',
  item          : url,
  port          : port,
  data          : data,
  content_type  : 'application/x-www-form-urlencoded',
  exit_on_fail  : TRUE
);

matches = pregmatch(string:res[2], pattern: "Can't move uploaded file.*to (.+/)"+filename);

if(matches)
{
  upload_dir = matches[1];
}
else
{
  exit(1, 'Failed to get the upload directory for ' + app + '.');
}

#
# Request 2: Test whether the server strips any illegal characater in
#   the 'filename' field. Ilegal characters are: !$^&*()~[]|{};<>?`/\ 
#
filename = './';
data = 'isofile.savepath=' + upload_dir + '&isofile.filename=' + filename;
res = http_send_recv3(
  method        : 'POST',
  item          : url,
  port          : port,
  data          : data,
  content_type  : 'application/x-www-form-urlencoded',
  exit_on_fail  : TRUE
);

if(empty_or_null(res[2]))
{
  audit(AUDIT_RESP_BAD, port, 'an HTTP POST request: No data in the response body');  
}

vuln_pat = "Can't move uploaded file.*to " + upload_dir + filename;
patched_pat = "Can't move uploaded file.*to " + upload_dir + 
  str_replace(string:filename,find:'/', replace:'');

if(res[2] =~ vuln_pat)
{
  extra = 'Nessus was able to detect the issues with the following request :\n\n' + http_last_sent_request();

  security_report_v4(
    port       : port,
    severity   : SECURITY_HOLE,
    extra      : extra
  );
}
else if(res[2] =~ patched_pat)
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:install['path'], port:port));
}
else
{
  audit(AUDIT_RESP_BAD, port, "an HTTP POST request." + ' Unexpected HTTP response body:\n' + res[2]);
}
