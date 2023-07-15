#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177469);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/06");

  script_cve_id("CVE-2023-34981");
  script_xref(name:"IAVA", value:"2023-A-0315");

  script_name(english:"Apache Tomcat 11.0.0.M1 < 11.0.0.M6");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 11.0.0.M6. It is, therefore, affected by a vulnerability
as referenced in the fixed_in_apache_tomcat_11.0.0-m6_security-11 advisory.

  - A regression in the fix for bug 66512 in Apache Tomcat 11.0.0-M5, 10.1.8, 9.0.74 and 8.5.88 meant that, if
    a response did not include any HTTP headers no AJP SEND_HEADERS messare woudl be sent for the response
    which in turn meant that at least one AJP proxy (mod_proxy_ajp) would use the response headers from the
    previous request leading to an information leak. (CVE-2023-34981)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bz.apache.org/bugzilla/show_bug.cgi?id=66512");
  script_set_attribute(attribute:"see_also", value:"https://bz.apache.org/bugzilla/show_bug.cgi?id=66591");
  # https://github.com/apache/tomcat/commit/739c7381aed22b7636351caf885ddc519ab6b442
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc141757");
  # https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.0-M6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?64c64918");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 11.0.0.M6 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-34981");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('tomcat_version.inc');

tomcat_check_version(fixed: '11.0.0.M6', min:'11.0.0.M1', severity:SECURITY_HOLE, granularity_regex: "^(11(\.0(\.0)?)?)$");
