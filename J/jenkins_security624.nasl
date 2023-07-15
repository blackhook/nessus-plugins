#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2018/06/27  Deprecated due to advisory updating it specifying Ant plugin which requires a local check.

include("compat.inc");

if (description)
{
  script_id(105293);
  script_version("1.9");
  script_cvs_date("Date: 2018/08/06 16:33:30");

  script_cve_id("CVE-2017-17383");
  script_bugtraq_id(102130);

  script_name(english:"Jenkins JDK / Ant Tools Job Configuration Stored XSS Vulnerability (SECURITY-624) (deprecated)");
  script_summary(english:"Checks the Jenkins version.");

  script_set_attribute(attribute:"synopsis", value:
"The Jenkins software installed on the remote host is affected
by a cross-site scripting Vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Jenkins advisory 2018-01-22 has updated to note this
vulnerability to be specific to the Ant plugin, which cannot
be accurately detected remotely with this plugin.  Thus this
plugin has been deprecated.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2017-12-05/");
# https://jenkins.io/security/advisory/2018-01-22/#xss-vulnerability-in-job-configuration-forms-in-ant-plugin
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59aa4c06");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/Jenkins");

  exit(0);
}

exit(0, "This plugin has been deprecated.");

