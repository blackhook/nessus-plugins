#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(143282);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

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
    93258,
    94112,
    94113,
    94114,
    94115,
    94117,
    94118,
    94366,
    95041,
    95042,
    95044,
    95047,
    95048,
    95049,
    95052,
    95055
  );

  script_name(english:"phpMyAdmin 4.0.0 < 4.0.10.17 / 4.4.0 < 4.4.15.8 / 4.6.0 < 4.6.4 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the phpMyAdmin application hosted on the remote web server is 4.0.x prior to
4.0.10.17, 4.4.x prior to 4.4.15.8, or 4.6.x prior to 4.6.4. It is, therefore, affected by multiple vulnerabilities.

  - An issue was discovered in cookie encryption in phpMyAdmin. The decryption of the username/password is
    vulnerable to a padding oracle attack. This can allow an attacker who has access to a user's browser
    cookie file to decrypt the username and password. Furthermore, the same initialization vector (IV) is used
    to hash the username and password stored in the phpMyAdmin cookie. If a user has the same password as
    their username, an attacker who examines the browser cookie can see that they are the same - but the
    attacker can not directly decode these values from the cookie as it is still hashed. All 4.6.x versions
    (prior to 4.6.4), 4.4.x versions (prior to 4.4.15.8), and 4.0.x versions (prior to 4.0.10.17) are
    affected. (CVE-2016-6606)

  - XSS issues were discovered in phpMyAdmin. This affects Zoom search (specially crafted column content can
    be used to trigger an XSS attack); GIS editor (certain fields in the graphical GIS editor are not properly
    escaped and can be used to trigger an XSS attack); Relation view; the following Transformations:
    Formatted, Imagelink, JPEG: Upload, RegexValidation, JPEG inline, PNG inline, and transformation wrapper;
    XML export; MediaWiki export; Designer; When the MySQL server is running with a specially-crafted log_bin
    directive; Database tab; Replication feature; and Database search. All 4.6.x versions (prior to 4.6.4),
    4.4.x versions (prior to 4.4.15.8), and 4.0.x versions (prior to 4.0.10.17) are affected. (CVE-2016-6607)

  - XSS issues were discovered in phpMyAdmin. This affects the database privilege check and the Remove
    partitioning functionality. Specially crafted database names can trigger the XSS attack. All 4.6.x
    versions (prior to 4.6.4) are affected. (CVE-2016-6608)

  - An issue was discovered in phpMyAdmin. A specially crafted database name could be used to run arbitrary
    PHP commands through the array export feature. All 4.6.x versions (prior to 4.6.4), 4.4.x versions (prior
    to 4.4.15.8), and 4.0.x versions (prior to 4.0.10.17) are affected. (CVE-2016-6609)

  - A full path disclosure vulnerability was discovered in phpMyAdmin where a user can trigger a particular
    error in the export mechanism to discover the full path of phpMyAdmin on the disk. All 4.6.x versions
    (prior to 4.6.4), 4.4.x versions (prior to 4.4.15.8), and 4.0.x versions (prior to 4.0.10.17) are
    affected. (CVE-2016-6610)

  - An issue was discovered in phpMyAdmin. A specially crafted database and/or table name can be used to
    trigger an SQL injection attack through the export functionality. All 4.6.x versions (prior to 4.6.4),
    4.4.x versions (prior to 4.4.15.8), and 4.0.x versions (prior to 4.0.10.17) are affected. (CVE-2016-6611)

  - An issue was discovered in phpMyAdmin. A user can exploit the LOAD LOCAL INFILE functionality to expose
    files on the server to the database system. All 4.6.x versions (prior to 4.6.4), 4.4.x versions (prior to
    4.4.15.8), and 4.0.x versions (prior to 4.0.10.17) are affected. (CVE-2016-6612)

  - An issue was discovered in phpMyAdmin. A user can specially craft a symlink on disk, to a file which
    phpMyAdmin is permitted to read but the user is not, which phpMyAdmin will then expose to the user. All
    4.6.x versions (prior to 4.6.4), 4.4.x versions (prior to 4.4.15.8), and 4.0.x versions (prior to
    4.0.10.17) are affected. (CVE-2016-6613)

  - An issue was discovered in phpMyAdmin involving the %u username replacement functionality of the SaveDir
    and UploadDir features. When the username substitution is configured, a specially-crafted user name can be
    used to circumvent restrictions to traverse the file system. All 4.6.x versions (prior to 4.6.4), 4.4.x
    versions (prior to 4.4.15.8), and 4.0.x versions (prior to 4.0.10.17) are affected. (CVE-2016-6614)

  - XSS issues were discovered in phpMyAdmin. This affects navigation pane and database/table hiding feature
    (a specially-crafted database name can be used to trigger an XSS attack); the Tracking feature (a
    specially-crafted query can be used to trigger an XSS attack); and GIS visualization feature. All 4.6.x
    versions (prior to 4.6.4) and 4.4.x versions (prior to 4.4.15.8) are affected. (CVE-2016-6615)

  - An issue was discovered in phpMyAdmin. In the User group and Designer features, a user can execute an
    SQL injection attack against the account of the control user. All 4.6.x versions (prior to 4.6.4) and
    4.4.x versions (prior to 4.4.15.8) are affected. (CVE-2016-6616)

  - An issue was discovered in phpMyAdmin. A specially crafted database and/or table name can be used to
    trigger an SQL injection attack through the export functionality. All 4.6.x versions (prior to 4.6.4) are
    affected. (CVE-2016-6617)

  - An issue was discovered in phpMyAdmin. The transformation feature allows a user to trigger a denial-of-
    service (DoS) attack against the server. All 4.6.x versions (prior to 4.6.4), 4.4.x versions (prior to
    4.4.15.8), and 4.0.x versions (prior to 4.0.10.17) are affected. (CVE-2016-6618)

  - An issue was discovered in phpMyAdmin. In the user interface preference feature, a user can execute an SQL
    injection attack against the account of the control user. All 4.6.x versions (prior to 4.6.4), 4.4.x
    versions (prior to 4.4.15.8), and 4.0.x versions (prior to 4.0.10.17) are affected. (CVE-2016-6619)

  - An issue was discovered in phpMyAdmin. Some data is passed to the PHP unserialize() function without
    verification that it's valid serialized data. The unserialization can result in code execution because of
    the interaction with object instantiation and autoloading. All 4.6.x versions (prior to 4.6.4), 4.4.x
    versions (prior to 4.4.15.8), and 4.0.x versions (prior to 4.0.10.17) are affected. (CVE-2016-6620)

  - An issue was discovered in phpMyAdmin. An unauthenticated user is able to execute a denial-of-service
    (DoS) attack by forcing persistent connections when phpMyAdmin is running with
    $cfg['AllowArbitraryServer']=true. All 4.6.x versions (prior to 4.6.4), 4.4.x versions (prior to
    4.4.15.8), and 4.0.x versions (prior to 4.0.10.17) are affected. (CVE-2016-6622)

  - An issue was discovered in phpMyAdmin. An authorized user can cause a denial-of-service (DoS) attack on a
    server by passing large values to a loop. All 4.6.x versions (prior to 4.6.4), 4.4.x versions (prior to
    4.4.15.8), and 4.0.x versions (prior to 4.0.10.17) are affected. (CVE-2016-6623)

  - An issue was discovered in phpMyAdmin involving improper enforcement of the IP-based authentication rules.
    When phpMyAdmin is used with IPv6 in a proxy server environment, and the proxy server is in the allowed
    range but the attacking computer is not allowed, this vulnerability can allow the attacking computer to
    connect despite the IP rules. All 4.6.x versions (prior to 4.6.4), 4.4.x versions (prior to 4.4.15.8), and
    4.0.x versions (prior to 4.0.10.17) are affected. (CVE-2016-6624)

  - An issue was discovered in phpMyAdmin. An attacker can determine whether a user is logged in to
    phpMyAdmin. The user's session, username, and password are not compromised by this vulnerability. All
    4.6.x versions (prior to 4.6.4), 4.4.x versions (prior to 4.4.15.8), and 4.0.x versions (prior to
    4.0.10.17) are affected. (CVE-2016-6625)

  - An issue was discovered in phpMyAdmin. An attacker could redirect a user to a malicious web page. All
    4.6.x versions (prior to 4.6.4), 4.4.x versions (prior to 4.4.15.8), and 4.0.x versions (prior to
    4.0.10.17) are affected. (CVE-2016-6626)

  - An issue was discovered in phpMyAdmin. An attacker can determine the phpMyAdmin host location through the
    file url.php. All 4.6.x versions (prior to 4.6.4), 4.4.x versions (prior to 4.4.15.8), and 4.0.x versions
    (prior to 4.0.10.17) are affected. (CVE-2016-6627)

  - An issue was discovered in phpMyAdmin. An attacker may be able to trigger a user to download a specially
    crafted malicious SVG file. All 4.6.x versions (prior to 4.6.4), 4.4.x versions (prior to 4.4.15.8), and
    4.0.x versions (prior to 4.0.10.17) are affected. (CVE-2016-6628)

  - An issue was discovered in phpMyAdmin involving the $cfg['ArbitraryServerRegexp'] configuration directive.
    An attacker could reuse certain cookie values in a way of bypassing the servers defined by
    ArbitraryServerRegexp. All 4.6.x versions (prior to 4.6.4), 4.4.x versions (prior to 4.4.15.8), and 4.0.x
    versions (prior to 4.0.10.17) are affected. (CVE-2016-6629)

  - An issue was discovered in phpMyAdmin. An authenticated user can trigger a denial-of-service (DoS) attack
    by entering a very long password at the change password dialog. All 4.6.x versions (prior to 4.6.4), 4.4.x
    versions (prior to 4.4.15.8), and 4.0.x versions (prior to 4.0.10.17) are affected. (CVE-2016-6630)

  - An issue was discovered in phpMyAdmin. A user can execute a remote code execution attack against a server
    when phpMyAdmin is being run as a CGI application. Under certain server configurations, a user can pass a
    query string which is executed as a command-line argument by the file generator_plugin.sh. All 4.6.x
    versions (prior to 4.6.4), 4.4.x versions (prior to 4.4.15.8), and 4.0.x versions (prior to 4.0.10.17) are
    affected. (CVE-2016-6631)

  - An issue was discovered in phpMyAdmin where, under certain conditions, phpMyAdmin may not delete temporary
    files during the import of ESRI files. All 4.6.x versions (prior to 4.6.4), 4.4.x versions (prior to
    4.4.15.8), and 4.0.x versions (prior to 4.0.10.17) are affected. (CVE-2016-6632)

  - An issue was discovered in phpMyAdmin. phpMyAdmin can be used to trigger a remote code execution attack
    against certain PHP installations that are running with the dbase extension. All 4.6.x versions (prior to
    4.6.4), 4.4.x versions (prior to 4.4.15.8), and 4.0.x versions (prior to 4.0.10.17) are affected.
    (CVE-2016-6633)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
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
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-55/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-56/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin version 4.0.10.17 / 4.4.15.8 / 4.6.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6629");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(661);

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/phpMyAdmin", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:'phpMyAdmin', port:port, webapp:TRUE);

constraints = [
  { 'min_version' : '4.0.0', 'fixed_version' : '4.0.10.17' },
  { 'min_version' : '4.4.0', 'fixed_version' : '4.4.15.8' },
  { 'min_version' : '4.6.0', 'fixed_version' : '4.6.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{xss:TRUE, sqli:TRUE});
