#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2019/10/21. Deprecated by apache_2_4_33.nasl (plugin ID 122060).

include("compat.inc");

if (description)
{
  script_id(108758);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id(
    "CVE-2017-15710",
    "CVE-2017-15715",
    "CVE-2018-1283",
    "CVE-2018-1301",
    "CVE-2018-1302",
    "CVE-2018-1303",
    "CVE-2018-1312"
  );
  script_bugtraq_id(
    103512,
    103515,
    103520,
    103522,
    103524,
    103525,
    103528
  );

  script_name(english:"Apache 2.4.x < 2.4.33 Multiple Vulnerabilities (deprecated)");
  script_summary(english:"Checks version in Server response header.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated due to apache_2_4_33.nasl (plugin ID 122060) performing the same version check. Use
apache_2_4_33.nasl (plugin ID 122060) instead.");
  script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/httpd/CHANGES_2.4.33");
  script_set_attribute(attribute:"see_also", value:"https://httpd.apache.org/security/vulnerabilities_24.html#2.4.33");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1312");
  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:httpd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_http_version.nasl", "apache_http_server_nix_installed.nbin", "apache_httpd_win_installed.nbin");
  script_require_keys("installed_sw/Apache");

  exit(0);
}
exit(0, "This plugin has been deprecated. Use apache_2_4_33.nasl (plugin ID 122060) instead.");