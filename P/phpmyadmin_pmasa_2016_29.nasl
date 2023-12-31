#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2020/12/22. Deprecated by phpmyadmin_pmasa_4_6_4.nasl (plugin ID 143282).

include("compat.inc");

if (description)
{
  script_id(95027);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/31");

  script_cve_id(
    "CVE-2016-6606",
    "CVE-2016-6607",
    "CVE-2016-6608",
    "CVE-2016-6609",
    "CVE-2016-6610",
    "CVE-2016-6611",
    "CVE-2016-6612",
    "CVE-2016-6613",
    "CVE-2016-6614",
    "CVE-2016-6615",
    "CVE-2016-6616",
    "CVE-2016-6617",
    "CVE-2016-6618",
    "CVE-2016-6619",
    "CVE-2016-6620",
    "CVE-2016-6622",
    "CVE-2016-6623",
    "CVE-2016-6624",
    "CVE-2016-6625",
    "CVE-2016-6626",
    "CVE-2016-6627",
    "CVE-2016-6628",
    "CVE-2016-6629",
    "CVE-2016-6630",
    "CVE-2016-6631",
    "CVE-2016-6632",
    "CVE-2016-6633"
  );
  script_bugtraq_id(
    92489,
    92490,
    92491,
    92492,
    92493,
    92494,
    92496,
    92497,
    92500,
    92501,
    93257,
    93258
  );

  script_name(english:"phpMyAdmin 4.0.x < 4.0.10.17 / 4.4.x < 4.4.15.8 / 4.6.x < 4.6.4 Multiple Vulnerabilities (PMASA-2016-29 - PMASA-2016-56) (deprecated)");
  script_summary(english:"Checks the version of phpMyAdmin.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the phpMyAdmin
application hosted on the remote web server is 4.0.x prior to
4.0.10.17, 4.4.x prior to 4.4.15.8, or 4.6.x prior to 4.6.4. It is,
therefore, affected by the following vulnerabilities :

  - An information disclosure vulnerability exists due to
    the use of an algorithm that is vulnerable to padding
    oracle attacks. An unauthenticated, remote attacker can
    exploit this to decrypt information without the key,
    resulting in the disclosure of usernames and passwords.
    (CVE-2016-6606)

  - A cross-site scripting (XSS) vulnerability exists in the
    replication_gui.lib.php script due to improper
    validation of user-supplied input to the 'username' and
    'hostname' parameters. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code in a user's
    browser session. (CVE-2016-6607)

  - A cross-site scripting (XSS) vulnerability exists in the
    database privilege check functionality and the remove
    partitioning functionality due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this, via a specially crafted request, to
    execute arbitrary script code in a user's browser
    session. Note that this vulnerability only affects 4.6.x
    versions. (CVE-2016-6608)

  - A remote command execution vulnerability exists in the
    ExportPhparray.class.php script due to improper
    validation of user-supplied input passed via database
    names. An authenticated, remote attacker can exploit
    this to execute arbitrary PHP commands. (CVE-2016-6609)

  - An information disclosure vulnerability exists in the
    plugin_interface.lib.php script due to improper handling
    of errors when creating non-existent classes. An
    authenticated, remote attacker can exploit this to
    disclose the installation path. (CVE-2016-6610)

  - A SQL injection vulnerability exists in the
    ExportSql.class.php script due to improper sanitization
    of user-supplied input to database and table names. An
    authenticated, remote attacker can exploit this to
    manipulate SQL queries in the back-end database,
    resulting in the manipulation and disclosure of
    arbitrary data. (CVE-2016-6611)

  - An information disclosure vulnerability exists in the
    LOAD LOCAL INFILE functionality that allows an
    authenticated, remote attacker to expose files on the
    server to the database system. (CVE-2016-6612)

  - An information disclosure vulnerability exists due to
    insecure creation of temporary files. A local attacker
    can exploit this, via a symlink attack, to disclose
    arbitrary files. (CVE-2016-6613)

  - A directory traversal vulnerability exists in the
    Util.class.php script due to improper sanitization of
    user-supplied input when handling the %u username
    replacement functionality of the SaveDir and UploadDir
    features. An unauthenticated, remote attacker can
    exploit this, via a specially crafted request, to
    disclose arbitrary files. (CVE-2016-6614)

  - Multiple cross-site scripting (XSS) vulnerabilities
    exist due to improper validation of user-supplied input.
    An unauthenticated, remote attacker can exploit these,
    via a specially crafted request, to execute arbitrary
    script code in a user's browser session. Note that these
    vulnerabilities do not affect 4.0.x versions.
    (CVE-2016-6615)

  - A SQL injection vulnerability exists due to improper
    sanitization of user-supplied input when handling user
    group queries. An authenticated, remote attacker can
    exploit this to manipulate SQL queries in the back-end
    database, resulting in the manipulation and disclosure
    of arbitrary data. Note that this vulnerability does not
    affect 4.0.x versions. (CVE-2016-6616)

  - A SQL injection vulnerability exists in the
    display_export.lib.php script due to improper
    sanitization of user-supplied input when handling
    database and table names. An authenticated, remote
    attacker can exploit this to manipulate SQL queries in
    the back-end database, resulting in the manipulation and
    disclosure of arbitrary data. Note that this
    vulnerability only affects 4.6.x versions.
    (CVE-2016-6617)

  - A denial of service vulnerability exists in the
    transformation_wrapper.php script due to improper
    scaling of image dimensions. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition. (CVE-2016-6618)

  - A SQL injection vulnerability exists in the user
    interface preference feature due to improper
    sanitization of user-supplied input. An authenticated,
    remote attacker can exploit this to manipulate SQL
    queries in the back-end database, resulting in the
    manipulation and disclosure of arbitrary data.
    (CVE-2016-6619)

  - A remote code execution vulnerability exists in the
    unserialize() function due to improper validation of
    user-supplied data. An unauthenticated, remote attacker
    can exploit this to execute arbitrary code.
    (CVE-2016-6620)

  - A denial of service vulnerability exists when the
    AllowArbitraryServer option is enabled that allows an
    unauthenticated, remote attacker to cause a denial of
    service condition by forcing a persistent connection.
    (CVE-2016-6622)

  - A denial of service vulnerability exists due to improper
    handling of looped larger values. An authenticated,
    remote attacker can exploit this to cause a denial of
    service condition. (CVE-2016-6623)

  - A security bypass vulnerability exists in the
    ip_allow_deny.lib.php script that allows an
    unauthenticated, remote attacker to bypass IP-based
    authentication rules. (CVE-2016-6624)

  - An information disclosure vulnerability exists that
    allows an unauthenticated, remote attacker to determine
    whether a user is logged in or not. (CVE-2016-6625)

  - A cross-site redirection vulnerability exists in the
    core.lib.php script due to a failure to validate
    user-supplied input. An unauthenticated, remote attacker
    can exploit this, by convincing a user to follow a
    specially crafted link, to redirect the user to an
    arbitrary website. (CVE-2016-6626)

  - An information disclosure vulnerability exists in the
    url.php script due to improper handling of HTTP headers.
    An unauthenticated, remote attacker can exploit this to
    disclose host location information. (CVE-2016-6627)

  - A flaw exists in the file_echo.php script that allows an
    unauthenticated, remote attacker to cause a different
    user to download a specially crafted SVG file.
    (CVE-2016-6628)

  - A flaw exists in the ArbitraryServerRegexp configuration
    directive that allows an unauthenticated, remote
    attacker to reuse certain cookie values and bypass
    intended server definition limits. (CVE-2016-6629)

  - A denial of service vulnerability exists in the
    user_password.php script due to improper handling of an
    overly long password. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition. (CVE-2016-6630)

  - A remote code execution vulnerability exists in the
    generator_plugin.sh script due to improper handling of
    query strings. An unauthenticated, remote attacker can
    exploit this to execute arbitrary code. (CVE-2016-6631)

  - A denial of service vulnerability exists in the dbase
    extension in the ImportShp.class.php script due to a
    failure to delete temporary files during the import of
    ESRI files. An unauthenticated, remote attacker can
    exploit this to cause a denial of service condition.
    (CVE-2016-6632)

  - A remote code execution vulnerability exists in the
    dbase extension due to improper handling of SHP imports.
    An unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2016-6633)

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.

This plugin has been deprecated. Use phpmyadmin_pmasa_4_6_4.nasl (plugin ID 143282) instead.");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-29/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-30/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-31/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-32/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-33/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-34/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-35/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-36/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-37/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-38/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-39/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-40/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-41/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-42/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-43/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-45/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-46/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-47/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-48/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-49/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-50/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-51/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-52/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-53/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-54/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-56/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6629");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/phpMyAdmin", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

exit(0, 'This plugin has been deprecated. Use phpmyadmin_pmasa_4_6_4.nasl (plugin ID 143282) instead.');
