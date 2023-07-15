#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:4069-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(167937);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id(
    "CVE-2017-8923",
    "CVE-2020-7068",
    "CVE-2020-7069",
    "CVE-2020-7070",
    "CVE-2020-7071",
    "CVE-2021-21702",
    "CVE-2021-21703",
    "CVE-2021-21704",
    "CVE-2021-21705",
    "CVE-2021-21706",
    "CVE-2021-21707",
    "CVE-2021-21708",
    "CVE-2022-31625",
    "CVE-2022-31626",
    "CVE-2022-31628",
    "CVE-2022-31629",
    "CVE-2022-31630",
    "CVE-2022-37454"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:4069-1");
  script_xref(name:"IAVA", value:"2021-A-0009-S");
  script_xref(name:"IAVA", value:"2020-A-0445-S");
  script_xref(name:"IAVA", value:"2022-A-0455-S");
  script_xref(name:"IAVA", value:"2021-A-0082-S");
  script_xref(name:"IAVA", value:"2020-A-0373-S");
  script_xref(name:"IAVA", value:"2022-A-0515-S");
  script_xref(name:"IAVA", value:"2021-A-0566");
  script_xref(name:"IAVA", value:"2022-A-0397");
  script_xref(name:"IAVA", value:"2021-A-0503-S");
  script_xref(name:"IAVB", value:"2017-B-0060-S");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : php7 (SUSE-SU-2022:4069-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2022:4069-1 advisory.

  - The zend_string_extend function in Zend/zend_string.h in PHP through 7.1.5 does not prevent changes to
    string objects that result in a negative length, which allows remote attackers to cause a denial of
    service (application crash) or possibly have unspecified other impact by leveraging a script's use of .=
    with a long string. (CVE-2017-8923)

  - In PHP versions 7.2.x below 7.2.33, 7.3.x below 7.3.21 and 7.4.x below 7.4.9, while processing PHAR files
    using phar extension, phar_parse_zipfile could be tricked into accessing freed memory, which could lead to
    a crash or information disclosure. (CVE-2020-7068)

  - In PHP versions 7.2.x below 7.2.34, 7.3.x below 7.3.23 and 7.4.x below 7.4.11, when AES-CCM mode is used
    with openssl_encrypt() function with 12 bytes IV, only first 7 bytes of the IV is actually used. This can
    lead to both decreased security and incorrect encryption data. (CVE-2020-7069)

  - In PHP versions 7.2.x below 7.2.34, 7.3.x below 7.3.23 and 7.4.x below 7.4.11, when PHP is processing
    incoming HTTP cookie values, the cookie names are url-decoded. This may lead to cookies with prefixes like
    __Host confused with cookies that decode to such prefix, thus leading to an attacker being able to forge
    cookie which is supposed to be secure. See also CVE-2020-8184 for more information. (CVE-2020-7070)

  - In PHP versions 7.3.x below 7.3.26, 7.4.x below 7.4.14 and 8.0.0, when validating URL with functions like
    filter_var($url, FILTER_VALIDATE_URL), PHP will accept an URL with invalid password as valid URL. This may
    lead to functions that rely on URL being valid to mis-parse the URL and produce wrong data as components
    of the URL. (CVE-2020-7071)

  - In PHP versions 7.3.x below 7.3.27, 7.4.x below 7.4.15 and 8.0.x below 8.0.2, when using SOAP extension to
    connect to a SOAP server, a malicious SOAP server could return malformed XML data as a response that would
    cause PHP to access a null pointer and thus cause a crash. (CVE-2021-21702)

  - In PHP versions 7.3.x up to and including 7.3.31, 7.4.x below 7.4.25 and 8.0.x below 8.0.12, when running
    PHP FPM SAPI with main FPM daemon process running as root and child worker processes running as lower-
    privileged users, it is possible for the child processes to access memory shared with the main process and
    write to it, modifying it in a way that would cause the root process to conduct invalid memory reads and
    writes, which can be used to escalate privileges from local unprivileged user to the root user.
    (CVE-2021-21703)

  - In PHP versions 7.3.x below 7.3.29, 7.4.x below 7.4.21 and 8.0.x below 8.0.8, when using Firebird PDO
    driver extension, a malicious database server could cause crashes in various database functions, such as
    getAttribute(), execute(), fetch() and others by returning invalid response data that is not parsed
    correctly by the driver. This can result in crashes, denial of service or potentially memory corruption.
    (CVE-2021-21704)

  - In PHP versions 7.3.x below 7.3.29, 7.4.x below 7.4.21 and 8.0.x below 8.0.8, when using URL validation
    functionality via filter_var() function with FILTER_VALIDATE_URL parameter, an URL with invalid password
    field can be accepted as valid. This can lead to the code incorrectly parsing the URL and potentially
    leading to other security implications - like contacting a wrong server or making a wrong access decision.
    (CVE-2021-21705)

  - In PHP versions 7.3.x below 7.3.31, 7.4.x below 7.4.24 and 8.0.x below 8.0.11, in Microsoft Windows
    environment, ZipArchive::extractTo may be tricked into writing a file outside target directory when
    extracting a ZIP file, thus potentially causing files to be created or overwritten, subject to OS
    permissions. (CVE-2021-21706)

  - In PHP versions 7.3.x below 7.3.33, 7.4.x below 7.4.26 and 8.0.x below 8.0.13, certain XML parsing
    functions, like simplexml_load_file(), URL-decode the filename passed to them. If that filename contains
    URL-encoded NUL character, this may cause the function to interpret this as the end of the filename, thus
    interpreting the filename differently from what the user intended, which may lead it to reading a
    different file than intended. (CVE-2021-21707)

  - In PHP versions 7.4.x below 7.4.28, 8.0.x below 8.0.16, and 8.1.x below 8.1.3, when using filter functions
    with FILTER_VALIDATE_FLOAT filter and min/max limits, if the filter fails, there is a possibility to
    trigger use of allocated memory after free, which can result it crashes, and potentially in overwrite of
    other memory chunks and RCE. This issue affects: code that uses FILTER_VALIDATE_FLOAT with min/max limits.
    (CVE-2021-21708)

  - In PHP versions 7.4.x below 7.4.30, 8.0.x below 8.0.20, and 8.1.x below 8.1.7, when using Postgres
    database extension, supplying invalid parameters to the parametrized query may lead to PHP attempting to
    free memory using uninitialized data as pointers. This could lead to RCE vulnerability or denial of
    service. (CVE-2022-31625)

  - In PHP versions 7.4.x below 7.4.30, 8.0.x below 8.0.20, and 8.1.x below 8.1.7, when pdo_mysql extension
    with mysqlnd driver, if the third party is allowed to supply host to connect to and the password for the
    connection, password of excessive length can trigger a buffer overflow in PHP, which can lead to a remote
    code execution vulnerability. (CVE-2022-31626)

  - In PHP versions before 7.4.31, 8.0.24 and 8.1.11, the phar uncompressor code would recursively uncompress
    quines gzip files, resulting in an infinite loop. (CVE-2022-31628)

  - In PHP versions before 7.4.31, 8.0.24 and 8.1.11, the vulnerability enables network and same-site
    attackers to set a standard insecure cookie in the victim's browser which is treated as a `__Host-` or
    `__Secure-` cookie by PHP applications. (CVE-2022-31629)

  - In PHP versions prior to 7.4.33, 8.0.25 and 8.2.12, when using imageloadfont() function in gd extension,
    it is possible to supply a specially crafted font file, such as if the loaded font is used with
    imagechar() function, the read outside allocated buffer will be used. This can lead to crashes or
    disclosure of confidential information. (CVE-2022-31630)

  - The Keccak XKCP SHA-3 reference implementation before fdc6fef has an integer overflow and resultant buffer
    overflow that allows attackers to execute arbitrary code or eliminate expected cryptographic properties.
    This occurs in the sponge function interface. (CVE-2022-37454)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203870");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204979");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-November/012985.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d37461b9");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-8923");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-7068");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-7069");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-7070");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-7071");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21702");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21703");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21704");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21705");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21706");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21707");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21708");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-31625");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-31626");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-31628");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-31629");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-31630");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-37454");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8923");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-37454");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_php7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-ctype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-fastcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-fileinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-iconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-pcntl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-phar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-posix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-shmop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-sockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-sodium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-sysvmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-sysvsem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-sysvshm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-tokenizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-xmlreader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-xmlwriter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php7-zlib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15|SUSE15\.3|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP3", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(2|3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP2/3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'apache2-mod_php7-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-bcmath-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-bz2-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-calendar-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-ctype-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-curl-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-dba-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-devel-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-dom-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-enchant-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-exif-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-fastcgi-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-fileinfo-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-fpm-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-ftp-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-gd-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-gettext-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-gmp-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-iconv-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-intl-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-json-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-ldap-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-mbstring-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-mysql-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-odbc-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-opcache-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-openssl-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-pcntl-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-pdo-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-pgsql-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-phar-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-posix-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-readline-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-shmop-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-snmp-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-soap-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-sockets-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-sodium-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-sqlite-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-sysvmsg-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-sysvsem-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-sysvshm-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-tidy-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-tokenizer-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-xmlreader-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-xmlrpc-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-xmlwriter-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-xsl-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-zip-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-zlib-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'apache2-mod_php7-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-bcmath-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-bz2-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-calendar-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-ctype-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-curl-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-dba-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-devel-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-dom-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-embed-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-embed-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-enchant-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-exif-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-fastcgi-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-fileinfo-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-fpm-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-ftp-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-gd-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-gettext-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-gmp-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-iconv-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-intl-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-json-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-ldap-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-mbstring-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-mysql-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-odbc-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-opcache-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-openssl-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-pcntl-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-pdo-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-pgsql-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-phar-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-posix-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-readline-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-shmop-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-snmp-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-soap-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-sockets-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-sodium-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-sqlite-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-sysvmsg-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-sysvsem-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-sysvshm-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-tidy-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-tokenizer-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-xmlreader-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-xmlrpc-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-xmlwriter-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-xsl-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-zip-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'php7-zlib-7.4.33-150200.3.46.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'apache2-mod_php7-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-bcmath-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-bz2-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-calendar-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-ctype-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-curl-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-dba-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-devel-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-dom-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-enchant-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-exif-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-fastcgi-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-fileinfo-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-fpm-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-ftp-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-gd-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-gettext-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-gmp-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-iconv-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-intl-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-json-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-ldap-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-mbstring-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-mysql-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-odbc-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-opcache-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-openssl-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-pcntl-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-pdo-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-pgsql-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-phar-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-posix-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-readline-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-shmop-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-snmp-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-soap-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-sockets-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-sodium-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-sqlite-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-sysvmsg-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-sysvsem-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-sysvshm-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-tidy-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-tokenizer-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-xmlreader-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-xmlrpc-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-xmlwriter-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-xsl-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-zip-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'php7-zlib-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'apache2-mod_php7-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'apache2-mod_php7-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-bcmath-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-bcmath-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-bz2-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-bz2-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-calendar-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-calendar-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-ctype-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-ctype-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-curl-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-curl-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-dba-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-dba-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-devel-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-devel-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-dom-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-dom-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-enchant-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-enchant-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-exif-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-exif-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-fastcgi-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-fastcgi-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-fileinfo-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-fileinfo-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-fpm-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-fpm-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-ftp-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-ftp-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-gd-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-gd-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-gettext-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-gettext-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-gmp-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-gmp-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-iconv-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-iconv-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-intl-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-intl-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-json-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-json-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-ldap-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-ldap-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-mbstring-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-mbstring-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-mysql-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-mysql-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-odbc-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-odbc-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-opcache-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-opcache-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-openssl-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-openssl-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-pcntl-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-pcntl-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-pdo-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-pdo-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-pgsql-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-pgsql-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-phar-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-phar-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-posix-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-posix-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-readline-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-readline-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-shmop-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-shmop-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-snmp-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-snmp-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-soap-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-soap-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-sockets-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-sockets-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-sodium-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-sodium-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-sqlite-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-sqlite-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-sysvmsg-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-sysvmsg-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-sysvsem-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-sysvsem-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-sysvshm-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-sysvshm-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-tidy-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-tidy-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-tokenizer-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-tokenizer-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-xmlreader-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-xmlreader-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-xmlrpc-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-xmlrpc-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-xmlwriter-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-xmlwriter-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-xsl-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-xsl-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-zip-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-zip-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-zlib-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'php7-zlib-7.4.33-150200.3.46.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'apache2-mod_php7-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-bcmath-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-bz2-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-calendar-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-ctype-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-curl-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-dba-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-devel-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-dom-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-embed-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-enchant-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-exif-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-fastcgi-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-fileinfo-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-firebird-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-fpm-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-ftp-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-gd-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-gettext-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-gmp-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-iconv-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-intl-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-json-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-ldap-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-mbstring-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-mysql-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-odbc-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-opcache-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-openssl-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-pcntl-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-pdo-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-pgsql-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-phar-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-posix-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-readline-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-shmop-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-snmp-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-soap-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-sockets-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-sodium-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-sqlite-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-sysvmsg-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-sysvsem-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-sysvshm-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-test-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-tidy-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-tokenizer-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-xmlreader-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-xmlrpc-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-xmlwriter-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-xsl-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-zip-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-zlib-7.4.33-150200.3.46.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'php7-firebird-7.4.33-150200.3.46.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'apache2-mod_php7-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-bcmath-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-bz2-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-calendar-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-ctype-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-curl-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-dba-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-devel-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-dom-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-enchant-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-exif-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-fastcgi-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-fileinfo-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-fpm-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-ftp-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-gd-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-gettext-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-gmp-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-iconv-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-intl-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-json-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-ldap-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-mbstring-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-mysql-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-odbc-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-opcache-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-openssl-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-pcntl-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-pdo-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-pgsql-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-phar-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-posix-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-readline-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-shmop-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-snmp-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-soap-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-sockets-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-sodium-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-sqlite-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-sysvmsg-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-sysvsem-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-sysvshm-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-tidy-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-tokenizer-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-xmlreader-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-xmlrpc-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-xmlwriter-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-xsl-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-zip-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'php7-zlib-7.4.33-150200.3.46.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache2-mod_php7 / php7 / php7-bcmath / php7-bz2 / php7-calendar / etc');
}
