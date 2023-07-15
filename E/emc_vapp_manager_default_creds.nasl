#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106849);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2018-1216");
  script_xref(name:"IAVB", value:"2018-B-0027");
  script_xref(name:"TRA", value:"TRA-2018-03");

  script_name(english:"EMC vApp Manager Default Credentials");
  script_summary(english:"Attempts to authenticate with default credentials");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application uses default credentials.");
  script_set_attribute(attribute:"description", value:
"The EMC vApp Manager web application running on the remote host uses a
default set of credentials ('smc' / 'smc'). An unauthenticated, remote
attacker can exploit this issue to authenticate to the application
and perform actions allowed by the default account. Specifically,
the attacker can login and exploit a file upload RCE vulnerability
(CVE-2018-1215) to cause remote code execution on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2018/Feb/att-38/DSA-2018-024.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade the following products:
  - Dell EMC Unisphere for VMAX Virtual Appliance 8.4.0.18
    OVA hotfix 1090, service alert 1059, or later.
  - Dell EMC Unisphere for VMAX Virtual Appliance 8.4.0.18
    ISO upgrade hotfix 1089, service alert 1058, or later.
  - Dell EMC Solutions Enabler Virtual Appliance 8.4.0.21
    OVA hotfix 2058, service alert 1891, or later.
  - Dell EMC Solutions Enabler Virtual Appliance 8.4.0.21
    ISO upgrade hotfix 2057, service alert 1890, or later.
  - Dell EMC VASA Virtual Appliance 8.4.0.516 OVA, or later.
  - Dell EMC VASA Virtual Appliance 8.4.0.516 ISO upgrade, or later.
  - eMGMT 1.4.0.355 (Service Pack 6848), or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1216");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:unisphere");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:solutions_enabler");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:emc:vasa_provider_virtual_appliance");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:emc:vmax_embedded_management");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("emc_vapp_manager_detect.nbin");
  script_require_keys("installed_sw/EMC vApp Manager");
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("http.inc");

app = "EMC vApp Manager";

# Exit if app is not detected on the target host
get_install_count(app_name:app, exit_if_zero:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_http_port(default:5480);

# Exit if app is not detected on this port
install = get_single_install(app_name:app, port: port);

url = "/SE/app";
data = "user=smc&passwd=smc";
res = http_send_recv3(
  method        : "POST",
  item          : url,
  port          : port,
  data          : data,
  content_type  : 'application/x-www-form-urlencoded',
  exit_on_fail  : TRUE
);


# Vulnerable: Getting a session ID
if(res[0] =~ "^HTTP/[0-9.]+ 200" &&
   res[1] =~ "Set-Cookie: JSESSIONID=.*\." &&
   res[2] =~ "login=success"
  )
{
  req = http_last_sent_request();
  security_report_v4(
    port       : port,
    severity   : SECURITY_HOLE,
    request    : make_list(req),
    output     : res[2],
    line_limit : 100,
    generic    : TRUE
  );
}
# Patched
else
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:install['path'], port:port));
}
