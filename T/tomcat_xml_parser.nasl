#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(39479);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2009-0783");
  script_bugtraq_id(35416);
  script_xref(name:"SECUNIA", value:"35326");
  script_xref(name:"SECUNIA", value:"35344");

  script_name(english:"Apache Tomcat Cross-Application File Manipulation");

  script_set_attribute(attribute:"synopsis", value:
"The web server running on the remote host is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote host is
running a vulnerable version of Apache Tomcat. Affected versions
permit a web application to replace the XML parser used to process the
XML and TLD files of other applications. This could allow a malicious
web app to read or modify 'web.xml', 'context.xml', or TLD files of
arbitrary web applications.");
  script_set_attribute(attribute:"see_also", value:"https://bz.apache.org/bugzilla/show_bug.cgi?id=29936");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/504090");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-6.html");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-5.html");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-4.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to versions 7.0.19 / 6.0.20 / 5.5.28 / 4.1.40 or later.
Alternatively, apply the patches referenced in the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-0783");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200);

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include("tomcat_version.inc");

tomcat_check_version(fixed:make_list("7.0.19", "6.0.20", "5.5.28", "4.1.40"), severity:SECURITY_WARNING, granularity_regex:"^(7(\.0)?|6(\.0)?|5(\.5)?|4(\.1)?)$");
