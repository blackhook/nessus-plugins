#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133845);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/11");

  script_cve_id("CVE-2019-17569", "CVE-2020-1935", "CVE-2020-1938");
  script_xref(name:"IAVB", value:"2020-B-0010-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");
  script_xref(name:"CEA-ID", value:"CEA-2020-0021");

  script_name(english:"Apache Tomcat 7.0.x < 7.0.100 / 8.5.x < 8.5.51 / 9.0.x < 9.0.31 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is 7.0.x prior to 7.0.100, 8.x prior to 8.5.51, or 9.0.x prior to 9.0.31. It
is, therefore, affected by multiple vulnerabilities.

  - An HTTP request smuggling vulnerability exists in Tomcat due to mishandling Transfer-Encoding headers
    behind a reverse proxy. An unauthenticated, remote attacker can exploit this, via crafted HTTP requests,
    to cause unintended HTTP requests to reach the back-end. (CVE-2019-17569)

  - An HTTP request smuggling vulnerability exists in Tomcat due to bad end-of-line (EOL) parsing that allowed
    some invalid HTTP headers to be parsed as valid. An unauthenticated, remote attacker can exploit this, via
    crafted HTTP requests, to cause unintended HTTP requests to reach the back-end. (CVE-2020-1935)

  - An arbitrary file read vulnerability exists in Tomcat's Apache JServ Protocol (AJP) due to an
    implementation defect. A remote, unauthenticated attacker could exploit this to access files which, under
    normal conditions, would be restricted. If the Tomcat instance supports file uploads, the vulnerability
    could also be leveraged to achieve remote code execution. (CVE-2020-1938)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.cnvd.org.cn/webinfo/show/5415");
  # https://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.100
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ebe6246");
  # https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.51
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e287adb");
  # https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.31
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cbc3d54e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 7.0.100, 8.5.51, 9.0.31 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1938");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('tomcat_version.inc');
tomcat_check_version(
  fixed:make_list("7.0.100", "8.5.51", "9.0.31"),
  severity:SECURITY_HOLE,
  granularity_regex:"^(7(\.0)?|8(\.5)?|9(\.0)?)$"
);
