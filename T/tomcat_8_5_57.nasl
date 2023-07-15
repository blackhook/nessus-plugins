#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(138574);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-13934", "CVE-2020-13935");
  script_xref(name:"IAVA", value:"2020-A-0316-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Apache Tomcat 8.5.0 < 8.5.57 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is 8.5.x prior to 8.5.57. It is, therefore, affected by multiple
vulnerabilities as referenced in the Fixed in Apache Tomcat 8.5.57 security advisory.

  - The payload length in a WebSocket frame was not correctly validated. Invalid payload lengths could trigger
    an infinite loop. Multiple requests with invalid payload lengths could lead to a denial of service (DoS).
    (CVE-2020-13935)

  - An h2c direct connection did not release the HTTP/1.1 processor after the upgrade to HTTP/2. If a
    sufficient number of such requests were made, an OutOfMemoryException could occur leading to a denial of
    service (DoS). (CVE-2020-13934)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/tomcat/commit/12d715676038efbf9c728af10163f8277fc019d5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cd59de72");
  # https://github.com/apache/tomcat/commit/923d834500802a61779318911d7898bd85fc950e
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7358785a");
  # https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.57
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?78f0e4ba");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 8.5.57 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13935");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "apache_tomcat_nix_installed.nbin", "tomcat_win_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('tomcat_version.inc');

tomcat_check_version(fixed: '8.5.57', min:'8.5.0', severity:SECURITY_WARNING, granularity_regex: "^8(\.5)?$");
