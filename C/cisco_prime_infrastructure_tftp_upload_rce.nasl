#
# (C) Tenable Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(118145);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id("CVE-2018-15379");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20181003-pi-tftp");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk24890");

  script_name(english:"Cisco Prime Infrastructure TFTP Arbitrary File Upload and Command Execution Vulnerability (cisco-sa-20181003-pi-tftp)");
  script_summary(english:"Attempts to detect the vulnerability.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Cisco Prime Infrastructure application running on the
remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Cisco Prime Infrastructure application running on the remote host
is affected by an arbitrary file upload flaw, which could lead to a
remote code execution vulnerability. This is due to incorrect
permissions for various system folders, which a file could be uploaded
to via TFTP. The commands in that file could then executes at the
privilege level of the user prime or root.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181003-pi-tftp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?35ef295a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Prime Infrastructure version 3.3.1 Update 02, 3.4.1,
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15379");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Cisco Prime Infrastructure Unauthenticated Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_infrastructure");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_infrastructure_detect.nbin", "tftpd_detect.nasl");
  script_require_keys("installed_sw/Prime Infrastructure", "Services/udp/tftp");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("install_func.inc");

# Make sure PI is detected
appname = "Prime Infrastructure";
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:443);
install = get_single_install(
  app_name:appname,
  port:port,
  exit_if_unknown_ver:FALSE);

ver = install["version"];

# cisco-sa-20181003-pi-tftp suggests versions prior to 3.2 are not affected
if(ver != UNKNOWN_VER &&
   ! empty_or_null((match = pregmatch(pattern:"([0-9.]+)", string:ver))) &&
   ver_compare(ver:match[1], fix:"3.2", strict:FALSE) == -1
)
{
  audit(AUDIT_HOST_NOT, "affected. Cisco Prime Infrastructure version is " + ver);
}

# Not affected if no TFTP server is detected (i.e., 3.2 FIPS)
if(! get_kb_item("Services/udp/tftp")) 
  audit(AUDIT_HOST_NOT, "affected. A TFTP server is not running on the remote host");
# Other files that can be used for testing:
#   poap_script.py.md5
#   prime-wsa-apache-server.crt
file = "poap_script.py";
res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : "/swimtemp/" + file,
  exit_on_fail : TRUE
);

if (res[0] =~ "^HTTP/.+ 200")
{
  extra = "Nessus was able to detect the issue with the following request : " +
    '\n\n' + http_last_sent_request();

  security_report_v4(
    port       : port,
    severity   : SECURITY_HOLE,
    extra      : extra
  );
}
else if (res[0] =~ "^HTTP/.+ 404")
{
  audit(AUDIT_HOST_NOT , "affected");
}
# Unexpected HTTP status
else
{
  audit(AUDIT_RESP_BAD , port, "an HTTP request. HTTP response status: " + res[0]);
}
