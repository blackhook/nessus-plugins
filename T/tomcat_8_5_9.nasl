#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(96003);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2016-8745");
  script_bugtraq_id(94828);

  script_name(english:"Apache Tomcat 6.0.16 < 6.0.50 / 7.0.x < 7.0.75 / 8.0.x < 8.0.41 / 8.5.x < 8.5.9 / 9.0.x < 9.0.0.M15 NIO HTTP Connector Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by an information
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Apache Tomcat
service running on the remote host is 6.0.16 prior to 6.0.50, 7.0.x
prior to 7.0.75, 8.0.x prior to 8.0.41, 8.5.x prior to 8.5.9, or 
9.0.x prior to 9.0.0.M15. It is therefore, affected by an information 
disclosure vulnerability in error handling during send file processing 
by the NIO HTTP connector, in which an error can cause the current 
Processor object to be added to the Processor cache multiple times. 
This allows the same Processor to be used for concurrent requests. 
An unauthenticated, remote attacker can exploit this issue, via a 
shared Processor, to disclose sensitive information, such as session 
IDs, response bodies related to another request, etc.

Note that Nessus has not attempted to exploit this issue but has
instead relied only on the application's self-reported version number.");
  # https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.0.M15
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3a06fd01");
  script_set_attribute(attribute:"see_also", value:"https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.9");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.0.41");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.75");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-6.html#Fixed_in_Apache_Tomcat_6.0.50");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 6.0.50 / 7.0.75 / 8.0.41 / 8.5.9 / 
9.0.0.M15 or later. For the 6.0.x version branch, the vulnerability 
was fixed in 6.0.49; however, that release candidate was not approved, 
and 6.0.50 is still pending release.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-8745");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include("tomcat_version.inc");
tomcat_check_version(fixed:make_list("6.0.50", "7.0.75", "8.0.41", "8.5.9", "9.0.0.M15"), severity:SECURITY_WARNING, granularity_regex:"^(6(\.0)?(\.([0-9]|[0-1][0-5]))?|7(\.0)?|8(\.(0|5))?|9(\.0)?)$");

