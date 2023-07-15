#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124058);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/20");

  script_cve_id("CVE-2019-0232");
  script_bugtraq_id(107906);

  script_name(english:"Apache Tomcat 9.0.0.M1 < 9.0.19 Remote Code Execution Vulnerability (Windows)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote Windows host is prior to 9.0.19. It is, therefore, affected by a remote
code execution vulnerability due to a bug in the way the JRE passes command line arguments to Windows. An 
unauthenticated, remote attacker can exploit this to execute arbitrary commands. 
Additionally, it is affected by a cross-site (XSS) scripting vulnerability as the SSI printenv command echoes user
provided data without proper escaping.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://codewhitesec.blogspot.com/2016/02/java-and-command-line-injections-in-windows.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ba5edc6");
  # https://web.archive.org/web/20161228144344/https://blogs.msdn.microsoft.com/twistylittlepassagesallalike/2011/04/23/everyone-quotes-command-line-arguments-the-wrong-way/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20cc80d0");
  # https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.18
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a563f9f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 9.0.18 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0232");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Tomcat CGIServlet enableCmdLineArguments Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_tomcat_nix_installed.nbin", "tomcat_error_version.nasl", "tomcat_win_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat", "Host/OS");

  exit(0);
}

include('tomcat_version.inc');

# Vuln only on Windows
os = get_kb_item_or_exit('Host/OS');
if ('Windows' >!< os) audit(AUDIT_OS_NOT, 'Windows', os);

conf = get_kb_item('Host/OS/Confidence');
if ((conf <= 70) && (report_paranoia < 2 )) 
{
  exit(1, 'Can\'t determine the host\'s OS with sufficient confidence and \'show potential false alarms\' is not enabled.');
}

tomcat_check_version(fixed: '9.0.19', min:'9.0.0.M1', severity:SECURITY_HOLE, granularity_regex: "^9(\.0)?$");
