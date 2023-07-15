#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(118088);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id("CVE-2018-15379");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20181003-pi-tftp");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk24890");

  script_name(english:"Cisco Prime Infrastructure TFTP Arbitrary File Upload and Command Execution Vulnerability (cisco-sa-20181003-pi-tftp)");
  script_summary(english:"Checks the version of Cisco Prime Infrastructure.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Cisco Prime Infrastructure application running on the
remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Cisco Prime Infrastructure application running on the remote host 
is affected by an arbitrary file upload flaw, which could lead to a
remote code execution vulnerability. This is due to incorrect
permissions for various system folders, which a file could be uploaded
to via TFTP. The commands in that file could then executes the prime
or root privilege level.");
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
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_infrastructure");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_infrastructure_detect.nbin");
  script_require_keys("installed_sw/Prime Infrastructure");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("install_func.inc");

appname = "Prime Infrastructure";
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:443);
install = get_single_install(
  app_name:appname,
  port:port,
  exit_if_unknown_ver:TRUE);

# Version may have ()
version = ereg_replace(string:install['version'], pattern:"[()]", replace:".");

if ("fips" >< tolower(ver)) exit(0,"TFTP disabled by default, no fix aviable.");
else
{
  # Lets clean out any extra crap
  matches = pregmatch(pattern:"([0-9.]+)", string:version);
  if (isnull(matches) || isnull(matches[1])) audit(AUDIT_VER_FORMAT, version);
  ver = matches[1];
}

fix = '';

if (ver_compare(fix:'3.3.1.2', ver:ver, minver:'3.2', strict:FALSE) < 0)
  fix = '3.3(1.2)';
else if (ver_compare(fix:'3.4.1', ver:ver, minver:'3.4', strict:FALSE) < 0)
  fix = '3.4(1.0)';
else audit(AUDIT_HOST_NOT, "affected");

if (!empty_or_null(fix))
{
  report = '\n  Version : ' + ver +
           '\n  Fix     : ' + fix;

  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_HOST_NOT, "affected");
