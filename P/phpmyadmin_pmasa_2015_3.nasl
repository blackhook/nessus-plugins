#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2020/12/22. Deprecated by phpmyadmin_pmasa_4_4_6_1.nasl (plugin ID 143273).

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(83732);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2015-3902", "CVE-2015-3903");
  script_bugtraq_id(74657, 74660);

  script_name(english:"phpMyAdmin 4.0.x < 4.0.10.10 / 4.2.x < 4.2.13.3 / 4.3.x < 4.3.13.1 / 4.4.x < 4.4.6.1 Multiple Vulnerabilities (PMASA-2015-2, PMASA-2015-3) (deprecated)");
  script_summary(english:"Checks the version of phpMyAdmin.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the phpMyAdmin
application hosted on the remote web server is 4.0.x prior to
4.0.10.10, 4.2.x prior to 4.2.13.3, 4.3.x prior to 4.3.13.1, or 4.4.x
prior to 4.4.6.1. It is, therefore, potentially affected by multiple
vulnerabilities:

  - An attacker could trick a user with a crafted URL during
    installation to alter the configuration file being
    generated. (CVE-2015-3902)

  - A flaw exits in 'Config.class.php', due to an error in
    an API call to GitHub, that allows a man-in-the-middle
    attacker to perform unauthorized actions.
    (CVE-2015-3903)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.

This plugin has been deprecated. Use phpmyadmin_pmasa_4_4_6_1.nasl (plugin ID 143273) instead.");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2015-2.php");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2015-3.php");
  # PMASA-2015-2
  # 4.4 https://github.com/phpmyadmin/phpmyadmin/commit/ee92eb9bab8e2d546756c1d4aec81ec7c8e44b83
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e995f404");
  # 4.3 https://github.com/phpmyadmin/phpmyadmin/commit/9817bd4030de949ba9ce4cd1b3f047e22d8f66bd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c7f08b0");
  # 4.2 https://github.com/phpmyadmin/phpmyadmin/commit/c903ecf6751684b6af2d079c78b1f0d09ea2bd47
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?37e50c37");
  # 4.0 https://github.com/phpmyadmin/phpmyadmin/commit/fea1d39fef540afa4105c6fbcc849f7e516f3da8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?21f1371b");

  # PMASA-2015-3
  # 4.4 https://github.com/phpmyadmin/phpmyadmin/commit/5ebc4daf131dd3bd646326267f3e765d0249bbb4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c563b16");
  # 4.3 https://github.com/phpmyadmin/phpmyadmin/commit/75499e790429c491840a0ad31d4de84aca215d23
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b6ae04d9");
  # 4.2 https://github.com/phpmyadmin/phpmyadmin/commit/0e18931d9e4b23053285b6fddf3493ca426ff684
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5388d172");
  # 4.0 https://github.com/phpmyadmin/phpmyadmin/commit/e97e7fb0ea2dedfaa95c7dbe872027fb4bd4204c
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?daf387cd");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2021 Tenable Network Security, Inc.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "installed_sw/phpMyAdmin", "Settings/ParanoidReport");

  exit(0);
}

exit(0, 'This plugin has been deprecated. Use phpmyadmin_pmasa_4_4_6_1.nasl (plugin ID 143273) instead.');
