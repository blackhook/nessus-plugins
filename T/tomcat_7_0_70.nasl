#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(121119);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2016-3092");

  script_name(english:"Apache Tomcat 7.0.x < 7.0.70 / 8.0.x < 8.0.36 / 8.5.x < 8.5.3 / 9.0.x < 9.0.0.M8 Denial of Service");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a 
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Apache Tomcat
instance listening on the remote host is 7.0.x prior to 7.0.70,
8.0.x < 8.0.36, 8.5.x < 8.5.3 or 9.0.x < 9.0.0.M8. It is,
therefore, affected by a denial of service vulnerability:

  - A denial of service vulnerability was identified in
    Commons FileUpload that occurred when the length of the
    multipart boundary was just below the size of the buffer
    (4096 bytes) used to read the uploaded file if the
    boundary was the typical tens of bytes long.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.70");
  # http://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.3_and_8.0.36
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ecb3da27");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.0.M8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 7.0.70 / 8.0.36 / 8.5.3 / 9.0.0.M8 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3092");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/11");

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

include("tomcat_version.inc");

tomcat_check_version(fixed:make_list("7.0.70", "8.0.36", "8.5.3", "9.0.0.M8"), severity:SECURITY_HOLE, granularity_regex:"^(7(\.0)?|8(\.(0|5))?|9(\.0)?)$");

