#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156860);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/13");

  script_cve_id(
    "CVE-2019-17571",
    "CVE-2020-9488",
    "CVE-2022-23302",
    "CVE-2022-23305",
    "CVE-2022-23307",
    "CVE-2023-26464"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Apache Log4j 1.x Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A logging library running on the remote host has multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of Apache Log4j on the remote host is 1.x and is no
longer supported. Log4j reached its end of life prior to 2016. Additionally, Log4j 1.x is affected by multiple
vulnerabilities, including :

  - Log4j includes a SocketServer that accepts serialized log events and deserializes them without verifying whether
    the objects are allowed or not. This can provide an attack vector that can be exploited. (CVE-2019-17571)

  - Improper validation of certificate with host mismatch in Apache Log4j SMTP appender. This could allow an SMTPS
    connection to be intercepted by a man-in-the-middle attack which could leak any log messages sent through that
    appender. (CVE-2020-9488)

  - JMSSink uses JNDI in an unprotected manner allowing any application using the JMSSink to be vulnerable if it is
    configured to reference an untrusted site or if the site referenced can be accesseed by the attacker.
    (CVE-2022-23302)

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it is
likely to contain security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://logging.apache.org/log4j/1.2/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Apache Log4j that is currently supported.

Upgrading to the latest versions for Apache Log4j is highly recommended as intermediate 
versions / patches have known high severity vulnerabilities and the vendor is updating 
their advisories often as new research and knowledge about the impact of Log4j is 
discovered. Refer to https://logging.apache.org/log4j/2.x/security.html for the latest 
versions.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23307");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-23305");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:log4j");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_log4j_win_installed.nbin", "apache_log4j_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Log4j");

  exit(0);
}

include('vcf.inc');

var app = 'Apache Log4j';
var win_local = FALSE;

if (get_kb_item('SMB/Registry/Enumerated'))
  win_local = TRUE;

var app_info = vcf::get_app_info(app:app, win_local:win_local);

var ver  = app_info['version'];
var path = app_info['path'];
var port = app_info['port'];

if (!port)
  port = 0;

# audit if version >= 2
if (ver_compare(ver:ver, fix:'2.0', strict:FALSE) >= 0)
  vcf::audit(app_info);

var report = strcat(
  '\n  Path              : ', path,
  '\n  Installed version : ', ver,
  '\n');

security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
