#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132418);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-17563");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Apache Tomcat 8.5.0 < 8.5.50 Privilege Escalation Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a privilege escalation vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 8.5.50. It is, therefore, affected by a privilege
escalation vulnerability as referenced in the 'Fixed in Apache Tomcat 8.5.50' advisory.

  - When using FORM authentication there was a narrow window where an attacker could perform a session
    fixation attack. The window was considered too narrow for an exploit to be practical but, erring on the
    side of caution, this issue has been treated as a security vulnerability. (CVE-2019-17563)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/apache/tomcat/commit/e19a202");
  # https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.50
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0b173ef");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 8.5.50 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17563");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('tomcat_version.inc');

tomcat_check_version(fixed:'8.5.50', min:'8.5.0', severity:SECURITY_WARNING, granularity_regex:"^8(\.5)?$");
