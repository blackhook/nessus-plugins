##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:3662. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(140396);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id(
    "CVE-2019-11039",
    "CVE-2019-11040",
    "CVE-2019-11041",
    "CVE-2019-11042",
    "CVE-2019-11045",
    "CVE-2019-11047",
    "CVE-2019-11048",
    "CVE-2019-11050",
    "CVE-2019-13224",
    "CVE-2019-13225",
    "CVE-2019-16163",
    "CVE-2019-19203",
    "CVE-2019-19204",
    "CVE-2019-19246",
    "CVE-2019-20454",
    "CVE-2020-7059",
    "CVE-2020-7060",
    "CVE-2020-7062",
    "CVE-2020-7063",
    "CVE-2020-7064",
    "CVE-2020-7065",
    "CVE-2020-7066"
  );
  script_bugtraq_id(108520, 108525);
  script_xref(name:"IAVA", value:"2020-A-0117-S");
  script_xref(name:"IAVA", value:"2020-A-0221-S");
  script_xref(name:"RHSA", value:"2020:3662");
  script_xref(name:"IAVA", value:"2020-A-0006-S");
  script_xref(name:"IAVA", value:"2020-A-0039-S");
  script_xref(name:"IAVB", value:"2019-B-0045-S");
  script_xref(name:"IAVA", value:"2019-A-0437-S");
  script_xref(name:"IAVB", value:"2019-B-0070-S");
  script_xref(name:"IAVA", value:"2020-A-0081-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"RHEL 8 : php:7.3 (RHSA-2020:3662)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:3662 advisory.

  - php: Out-of-bounds read due to integer overflow in iconv_mime_decode_headers() (CVE-2019-11039)

  - php: Buffer over-read in exif_read_data() (CVE-2019-11040)

  - php: Heap buffer over-read in exif_scan_thumbnail() (CVE-2019-11041)

  - php: Heap buffer over-read in exif_process_user_comment() (CVE-2019-11042)

  - php: DirectoryIterator class accepts filenames with embedded \0 byte and treats them as terminating at
    that byte (CVE-2019-11045)

  - php: Information disclosure in exif_read_data() (CVE-2019-11047)

  - php: Integer wraparounds when receiving multipart forms (CVE-2019-11048)

  - php: Out of bounds read when parsing EXIF information (CVE-2019-11050)

  - oniguruma: Use-after-free in onig_new_deluxe() in regext.c (CVE-2019-13224)

  - oniguruma: NULL pointer dereference in match_at() in regexec.c (CVE-2019-13225)

  - oniguruma: Stack exhaustion in regcomp.c because of recursion in regparse.c (CVE-2019-16163)

  - oniguruma: Heap-based buffer over-read in function gb18030_mbc_enc_len in file gb18030.c (CVE-2019-19203)

  - oniguruma: Heap-based buffer over-read in function fetch_interval_quantifier in regparse.c
    (CVE-2019-19204)

  - oniguruma: Heap-based buffer overflow in str_lower_case_match in regexec.c (CVE-2019-19246)

  - pcre: Out of bounds read in JIT mode when \X is used in non-UTF mode (CVE-2019-20454)

  - php: Out of bounds read in php_strip_tags_ex (CVE-2020-7059)

  - php: Global buffer-overflow in mbfl_filt_conv_big5_wchar function (CVE-2020-7060)

  - php: NULL pointer dereference in PHP session upload progress (CVE-2020-7062)

  - php: Files added to tar with Phar::buildFromIterator have all-access permissions (CVE-2020-7063)

  - php: Information disclosure in exif_read_data() function (CVE-2020-7064)

  - php: Using mb_strtolower() function with UTF-32LE encoding leads to potential code execution
    (CVE-2020-7065)

  - php: Information disclosure in function get_headers (CVE-2020-7066)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-11039");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-11040");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-11041");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-11042");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-11045");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-11047");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-11048");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-11050");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-13224");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-13225");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-16163");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19203");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19204");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19246");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-20454");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-7059");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-7060");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-7062");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-7063");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-7064");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-7065");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-7066");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:3662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1724152");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1724154");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1728965");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1728970");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1735494");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1739459");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1739465");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1768997");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1777537");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1786570");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1786572");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1788258");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1797776");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1797779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1802061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1802068");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1808532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1808536");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1820601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1820604");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1820627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1837842");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-13224");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 120, 121, 125, 170, 190, 200, 284, 400, 416, 476, 674, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apcu-panel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libzip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libzip-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libzip-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pecl-apcu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pecl-apcu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pecl-rrd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pecl-xdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pecl-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-xmlrpc");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var appstreams = {
  'php:7.3': [
    {
      'repo_relative_urls': [
        'content/aus/rhel8/8.2/x86_64/appstream/debug',
        'content/aus/rhel8/8.2/x86_64/appstream/os',
        'content/aus/rhel8/8.2/x86_64/appstream/source/SRPMS',
        'content/aus/rhel8/8.2/x86_64/baseos/debug',
        'content/aus/rhel8/8.2/x86_64/baseos/os',
        'content/aus/rhel8/8.2/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.2/ppc64le/appstream/debug',
        'content/e4s/rhel8/8.2/ppc64le/appstream/os',
        'content/e4s/rhel8/8.2/ppc64le/appstream/source/SRPMS',
        'content/e4s/rhel8/8.2/ppc64le/baseos/debug',
        'content/e4s/rhel8/8.2/ppc64le/baseos/os',
        'content/e4s/rhel8/8.2/ppc64le/baseos/source/SRPMS',
        'content/e4s/rhel8/8.2/ppc64le/highavailability/debug',
        'content/e4s/rhel8/8.2/ppc64le/highavailability/os',
        'content/e4s/rhel8/8.2/ppc64le/highavailability/source/SRPMS',
        'content/e4s/rhel8/8.2/ppc64le/sap-solutions/debug',
        'content/e4s/rhel8/8.2/ppc64le/sap-solutions/os',
        'content/e4s/rhel8/8.2/ppc64le/sap-solutions/source/SRPMS',
        'content/e4s/rhel8/8.2/ppc64le/sap/debug',
        'content/e4s/rhel8/8.2/ppc64le/sap/os',
        'content/e4s/rhel8/8.2/ppc64le/sap/source/SRPMS',
        'content/e4s/rhel8/8.2/x86_64/appstream/debug',
        'content/e4s/rhel8/8.2/x86_64/appstream/os',
        'content/e4s/rhel8/8.2/x86_64/appstream/source/SRPMS',
        'content/e4s/rhel8/8.2/x86_64/baseos/debug',
        'content/e4s/rhel8/8.2/x86_64/baseos/os',
        'content/e4s/rhel8/8.2/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.2/x86_64/highavailability/debug',
        'content/e4s/rhel8/8.2/x86_64/highavailability/os',
        'content/e4s/rhel8/8.2/x86_64/highavailability/source/SRPMS',
        'content/e4s/rhel8/8.2/x86_64/sap-solutions/debug',
        'content/e4s/rhel8/8.2/x86_64/sap-solutions/os',
        'content/e4s/rhel8/8.2/x86_64/sap-solutions/source/SRPMS',
        'content/e4s/rhel8/8.2/x86_64/sap/debug',
        'content/e4s/rhel8/8.2/x86_64/sap/os',
        'content/e4s/rhel8/8.2/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.2/aarch64/appstream/debug',
        'content/eus/rhel8/8.2/aarch64/appstream/os',
        'content/eus/rhel8/8.2/aarch64/appstream/source/SRPMS',
        'content/eus/rhel8/8.2/aarch64/baseos/debug',
        'content/eus/rhel8/8.2/aarch64/baseos/os',
        'content/eus/rhel8/8.2/aarch64/baseos/source/SRPMS',
        'content/eus/rhel8/8.2/aarch64/codeready-builder/debug',
        'content/eus/rhel8/8.2/aarch64/codeready-builder/os',
        'content/eus/rhel8/8.2/aarch64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.2/aarch64/highavailability/debug',
        'content/eus/rhel8/8.2/aarch64/highavailability/os',
        'content/eus/rhel8/8.2/aarch64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.2/aarch64/supplementary/debug',
        'content/eus/rhel8/8.2/aarch64/supplementary/os',
        'content/eus/rhel8/8.2/aarch64/supplementary/source/SRPMS',
        'content/eus/rhel8/8.2/ppc64le/appstream/debug',
        'content/eus/rhel8/8.2/ppc64le/appstream/os',
        'content/eus/rhel8/8.2/ppc64le/appstream/source/SRPMS',
        'content/eus/rhel8/8.2/ppc64le/baseos/debug',
        'content/eus/rhel8/8.2/ppc64le/baseos/os',
        'content/eus/rhel8/8.2/ppc64le/baseos/source/SRPMS',
        'content/eus/rhel8/8.2/ppc64le/codeready-builder/debug',
        'content/eus/rhel8/8.2/ppc64le/codeready-builder/os',
        'content/eus/rhel8/8.2/ppc64le/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.2/ppc64le/highavailability/debug',
        'content/eus/rhel8/8.2/ppc64le/highavailability/os',
        'content/eus/rhel8/8.2/ppc64le/highavailability/source/SRPMS',
        'content/eus/rhel8/8.2/ppc64le/resilientstorage/debug',
        'content/eus/rhel8/8.2/ppc64le/resilientstorage/os',
        'content/eus/rhel8/8.2/ppc64le/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.2/ppc64le/sap-solutions/debug',
        'content/eus/rhel8/8.2/ppc64le/sap-solutions/os',
        'content/eus/rhel8/8.2/ppc64le/sap-solutions/source/SRPMS',
        'content/eus/rhel8/8.2/ppc64le/sap/debug',
        'content/eus/rhel8/8.2/ppc64le/sap/os',
        'content/eus/rhel8/8.2/ppc64le/sap/source/SRPMS',
        'content/eus/rhel8/8.2/ppc64le/supplementary/debug',
        'content/eus/rhel8/8.2/ppc64le/supplementary/os',
        'content/eus/rhel8/8.2/ppc64le/supplementary/source/SRPMS',
        'content/eus/rhel8/8.2/s390x/appstream/debug',
        'content/eus/rhel8/8.2/s390x/appstream/os',
        'content/eus/rhel8/8.2/s390x/appstream/source/SRPMS',
        'content/eus/rhel8/8.2/s390x/baseos/debug',
        'content/eus/rhel8/8.2/s390x/baseos/os',
        'content/eus/rhel8/8.2/s390x/baseos/source/SRPMS',
        'content/eus/rhel8/8.2/s390x/codeready-builder/debug',
        'content/eus/rhel8/8.2/s390x/codeready-builder/os',
        'content/eus/rhel8/8.2/s390x/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.2/s390x/highavailability/debug',
        'content/eus/rhel8/8.2/s390x/highavailability/os',
        'content/eus/rhel8/8.2/s390x/highavailability/source/SRPMS',
        'content/eus/rhel8/8.2/s390x/resilientstorage/debug',
        'content/eus/rhel8/8.2/s390x/resilientstorage/os',
        'content/eus/rhel8/8.2/s390x/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.2/s390x/sap/debug',
        'content/eus/rhel8/8.2/s390x/sap/os',
        'content/eus/rhel8/8.2/s390x/sap/source/SRPMS',
        'content/eus/rhel8/8.2/s390x/supplementary/debug',
        'content/eus/rhel8/8.2/s390x/supplementary/os',
        'content/eus/rhel8/8.2/s390x/supplementary/source/SRPMS',
        'content/eus/rhel8/8.2/x86_64/appstream/debug',
        'content/eus/rhel8/8.2/x86_64/appstream/os',
        'content/eus/rhel8/8.2/x86_64/appstream/source/SRPMS',
        'content/eus/rhel8/8.2/x86_64/baseos/debug',
        'content/eus/rhel8/8.2/x86_64/baseos/os',
        'content/eus/rhel8/8.2/x86_64/baseos/source/SRPMS',
        'content/eus/rhel8/8.2/x86_64/codeready-builder/debug',
        'content/eus/rhel8/8.2/x86_64/codeready-builder/os',
        'content/eus/rhel8/8.2/x86_64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.2/x86_64/highavailability/debug',
        'content/eus/rhel8/8.2/x86_64/highavailability/os',
        'content/eus/rhel8/8.2/x86_64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.2/x86_64/resilientstorage/debug',
        'content/eus/rhel8/8.2/x86_64/resilientstorage/os',
        'content/eus/rhel8/8.2/x86_64/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.2/x86_64/sap-solutions/debug',
        'content/eus/rhel8/8.2/x86_64/sap-solutions/os',
        'content/eus/rhel8/8.2/x86_64/sap-solutions/source/SRPMS',
        'content/eus/rhel8/8.2/x86_64/sap/debug',
        'content/eus/rhel8/8.2/x86_64/sap/os',
        'content/eus/rhel8/8.2/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.2/x86_64/supplementary/debug',
        'content/eus/rhel8/8.2/x86_64/supplementary/os',
        'content/eus/rhel8/8.2/x86_64/supplementary/source/SRPMS',
        'content/tus/rhel8/8.2/x86_64/appstream/debug',
        'content/tus/rhel8/8.2/x86_64/appstream/os',
        'content/tus/rhel8/8.2/x86_64/appstream/source/SRPMS',
        'content/tus/rhel8/8.2/x86_64/baseos/debug',
        'content/tus/rhel8/8.2/x86_64/baseos/os',
        'content/tus/rhel8/8.2/x86_64/baseos/source/SRPMS',
        'content/tus/rhel8/8.2/x86_64/highavailability/debug',
        'content/tus/rhel8/8.2/x86_64/highavailability/os',
        'content/tus/rhel8/8.2/x86_64/highavailability/source/SRPMS',
        'content/tus/rhel8/8.2/x86_64/nfv/debug',
        'content/tus/rhel8/8.2/x86_64/nfv/os',
        'content/tus/rhel8/8.2/x86_64/nfv/source/SRPMS',
        'content/tus/rhel8/8.2/x86_64/rt/debug',
        'content/tus/rhel8/8.2/x86_64/rt/os',
        'content/tus/rhel8/8.2/x86_64/rt/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'apcu-panel-5.1.17-1.module+el8.1.0+3189+a1bff096', 'sp':'2', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libzip-1.5.2-1.module+el8.1.0+3189+a1bff096', 'sp':'2', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libzip-devel-1.5.2-1.module+el8.1.0+3189+a1bff096', 'sp':'2', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libzip-tools-1.5.2-1.module+el8.1.0+3189+a1bff096', 'sp':'2', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-bcmath-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-cli-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-common-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-dba-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-dbg-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-devel-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-embedded-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-enchant-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-fpm-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-gd-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-gmp-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-intl-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-json-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-ldap-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-mbstring-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-mysqlnd-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-odbc-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-opcache-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pdo-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pear-1.10.9-1.module+el8.1.0+3189+a1bff096', 'sp':'2', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'php-pecl-apcu-5.1.17-1.module+el8.1.0+3189+a1bff096', 'sp':'2', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pecl-apcu-devel-5.1.17-1.module+el8.1.0+3189+a1bff096', 'sp':'2', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pecl-rrd-2.0.1-1.module+el8.2.0+4968+1d5097db', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pecl-xdebug-2.8.0-1.module+el8.2.0+4968+1d5097db', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pecl-zip-1.15.4-1.module+el8.1.0+3189+a1bff096', 'sp':'2', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pgsql-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-process-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-recode-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-snmp-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-soap-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-xml-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-xmlrpc-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE}
      ]
    },
    {
      'repo_relative_urls': [
        'content/aus/rhel8/8.4/x86_64/appstream/debug',
        'content/aus/rhel8/8.4/x86_64/appstream/os',
        'content/aus/rhel8/8.4/x86_64/appstream/source/SRPMS',
        'content/aus/rhel8/8.4/x86_64/baseos/debug',
        'content/aus/rhel8/8.4/x86_64/baseos/os',
        'content/aus/rhel8/8.4/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.4/aarch64/appstream/debug',
        'content/e4s/rhel8/8.4/aarch64/appstream/os',
        'content/e4s/rhel8/8.4/aarch64/appstream/source/SRPMS',
        'content/e4s/rhel8/8.4/aarch64/baseos/debug',
        'content/e4s/rhel8/8.4/aarch64/baseos/os',
        'content/e4s/rhel8/8.4/aarch64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.4/ppc64le/appstream/debug',
        'content/e4s/rhel8/8.4/ppc64le/appstream/os',
        'content/e4s/rhel8/8.4/ppc64le/appstream/source/SRPMS',
        'content/e4s/rhel8/8.4/ppc64le/baseos/debug',
        'content/e4s/rhel8/8.4/ppc64le/baseos/os',
        'content/e4s/rhel8/8.4/ppc64le/baseos/source/SRPMS',
        'content/e4s/rhel8/8.4/ppc64le/highavailability/debug',
        'content/e4s/rhel8/8.4/ppc64le/highavailability/os',
        'content/e4s/rhel8/8.4/ppc64le/highavailability/source/SRPMS',
        'content/e4s/rhel8/8.4/ppc64le/sap-solutions/debug',
        'content/e4s/rhel8/8.4/ppc64le/sap-solutions/os',
        'content/e4s/rhel8/8.4/ppc64le/sap-solutions/source/SRPMS',
        'content/e4s/rhel8/8.4/ppc64le/sap/debug',
        'content/e4s/rhel8/8.4/ppc64le/sap/os',
        'content/e4s/rhel8/8.4/ppc64le/sap/source/SRPMS',
        'content/e4s/rhel8/8.4/s390x/appstream/debug',
        'content/e4s/rhel8/8.4/s390x/appstream/os',
        'content/e4s/rhel8/8.4/s390x/appstream/source/SRPMS',
        'content/e4s/rhel8/8.4/s390x/baseos/debug',
        'content/e4s/rhel8/8.4/s390x/baseos/os',
        'content/e4s/rhel8/8.4/s390x/baseos/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/appstream/debug',
        'content/e4s/rhel8/8.4/x86_64/appstream/os',
        'content/e4s/rhel8/8.4/x86_64/appstream/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/baseos/debug',
        'content/e4s/rhel8/8.4/x86_64/baseos/os',
        'content/e4s/rhel8/8.4/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/highavailability/debug',
        'content/e4s/rhel8/8.4/x86_64/highavailability/os',
        'content/e4s/rhel8/8.4/x86_64/highavailability/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/nfv/debug',
        'content/e4s/rhel8/8.4/x86_64/nfv/os',
        'content/e4s/rhel8/8.4/x86_64/nfv/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/sap-solutions/debug',
        'content/e4s/rhel8/8.4/x86_64/sap-solutions/os',
        'content/e4s/rhel8/8.4/x86_64/sap-solutions/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/sap/debug',
        'content/e4s/rhel8/8.4/x86_64/sap/os',
        'content/e4s/rhel8/8.4/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/appstream/debug',
        'content/eus/rhel8/8.4/aarch64/appstream/os',
        'content/eus/rhel8/8.4/aarch64/appstream/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/baseos/debug',
        'content/eus/rhel8/8.4/aarch64/baseos/os',
        'content/eus/rhel8/8.4/aarch64/baseos/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/codeready-builder/debug',
        'content/eus/rhel8/8.4/aarch64/codeready-builder/os',
        'content/eus/rhel8/8.4/aarch64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/highavailability/debug',
        'content/eus/rhel8/8.4/aarch64/highavailability/os',
        'content/eus/rhel8/8.4/aarch64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/supplementary/debug',
        'content/eus/rhel8/8.4/aarch64/supplementary/os',
        'content/eus/rhel8/8.4/aarch64/supplementary/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/appstream/debug',
        'content/eus/rhel8/8.4/ppc64le/appstream/os',
        'content/eus/rhel8/8.4/ppc64le/appstream/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/baseos/debug',
        'content/eus/rhel8/8.4/ppc64le/baseos/os',
        'content/eus/rhel8/8.4/ppc64le/baseos/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/codeready-builder/debug',
        'content/eus/rhel8/8.4/ppc64le/codeready-builder/os',
        'content/eus/rhel8/8.4/ppc64le/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/highavailability/debug',
        'content/eus/rhel8/8.4/ppc64le/highavailability/os',
        'content/eus/rhel8/8.4/ppc64le/highavailability/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/resilientstorage/debug',
        'content/eus/rhel8/8.4/ppc64le/resilientstorage/os',
        'content/eus/rhel8/8.4/ppc64le/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/sap-solutions/debug',
        'content/eus/rhel8/8.4/ppc64le/sap-solutions/os',
        'content/eus/rhel8/8.4/ppc64le/sap-solutions/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/sap/debug',
        'content/eus/rhel8/8.4/ppc64le/sap/os',
        'content/eus/rhel8/8.4/ppc64le/sap/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/supplementary/debug',
        'content/eus/rhel8/8.4/ppc64le/supplementary/os',
        'content/eus/rhel8/8.4/ppc64le/supplementary/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/appstream/debug',
        'content/eus/rhel8/8.4/s390x/appstream/os',
        'content/eus/rhel8/8.4/s390x/appstream/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/baseos/debug',
        'content/eus/rhel8/8.4/s390x/baseos/os',
        'content/eus/rhel8/8.4/s390x/baseos/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/codeready-builder/debug',
        'content/eus/rhel8/8.4/s390x/codeready-builder/os',
        'content/eus/rhel8/8.4/s390x/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/highavailability/debug',
        'content/eus/rhel8/8.4/s390x/highavailability/os',
        'content/eus/rhel8/8.4/s390x/highavailability/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/resilientstorage/debug',
        'content/eus/rhel8/8.4/s390x/resilientstorage/os',
        'content/eus/rhel8/8.4/s390x/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/sap/debug',
        'content/eus/rhel8/8.4/s390x/sap/os',
        'content/eus/rhel8/8.4/s390x/sap/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/supplementary/debug',
        'content/eus/rhel8/8.4/s390x/supplementary/os',
        'content/eus/rhel8/8.4/s390x/supplementary/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/appstream/debug',
        'content/eus/rhel8/8.4/x86_64/appstream/os',
        'content/eus/rhel8/8.4/x86_64/appstream/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/baseos/debug',
        'content/eus/rhel8/8.4/x86_64/baseos/os',
        'content/eus/rhel8/8.4/x86_64/baseos/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/codeready-builder/debug',
        'content/eus/rhel8/8.4/x86_64/codeready-builder/os',
        'content/eus/rhel8/8.4/x86_64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/highavailability/debug',
        'content/eus/rhel8/8.4/x86_64/highavailability/os',
        'content/eus/rhel8/8.4/x86_64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/resilientstorage/debug',
        'content/eus/rhel8/8.4/x86_64/resilientstorage/os',
        'content/eus/rhel8/8.4/x86_64/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/sap-solutions/debug',
        'content/eus/rhel8/8.4/x86_64/sap-solutions/os',
        'content/eus/rhel8/8.4/x86_64/sap-solutions/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/sap/debug',
        'content/eus/rhel8/8.4/x86_64/sap/os',
        'content/eus/rhel8/8.4/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/supplementary/debug',
        'content/eus/rhel8/8.4/x86_64/supplementary/os',
        'content/eus/rhel8/8.4/x86_64/supplementary/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/appstream/debug',
        'content/tus/rhel8/8.4/x86_64/appstream/os',
        'content/tus/rhel8/8.4/x86_64/appstream/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/baseos/debug',
        'content/tus/rhel8/8.4/x86_64/baseos/os',
        'content/tus/rhel8/8.4/x86_64/baseos/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/highavailability/debug',
        'content/tus/rhel8/8.4/x86_64/highavailability/os',
        'content/tus/rhel8/8.4/x86_64/highavailability/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/nfv/debug',
        'content/tus/rhel8/8.4/x86_64/nfv/os',
        'content/tus/rhel8/8.4/x86_64/nfv/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/rt/debug',
        'content/tus/rhel8/8.4/x86_64/rt/os',
        'content/tus/rhel8/8.4/x86_64/rt/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'apcu-panel-5.1.17-1.module+el8.1.0+3189+a1bff096', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libzip-1.5.2-1.module+el8.1.0+3189+a1bff096', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libzip-devel-1.5.2-1.module+el8.1.0+3189+a1bff096', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libzip-tools-1.5.2-1.module+el8.1.0+3189+a1bff096', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-bcmath-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-cli-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-common-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-dba-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-dbg-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-devel-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-embedded-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-enchant-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-fpm-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-gd-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-gmp-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-intl-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-json-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-ldap-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-mbstring-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-mysqlnd-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-odbc-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-opcache-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pdo-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pear-1.10.9-1.module+el8.1.0+3189+a1bff096', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'php-pecl-apcu-5.1.17-1.module+el8.1.0+3189+a1bff096', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pecl-apcu-devel-5.1.17-1.module+el8.1.0+3189+a1bff096', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pecl-rrd-2.0.1-1.module+el8.2.0+4968+1d5097db', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pecl-xdebug-2.8.0-1.module+el8.2.0+4968+1d5097db', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pecl-zip-1.15.4-1.module+el8.1.0+3189+a1bff096', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pgsql-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-process-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-recode-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-snmp-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-soap-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-xml-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-xmlrpc-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE}
      ]
    },
    {
      'repo_relative_urls': [
        'content/aus/rhel8/8.6/x86_64/appstream/debug',
        'content/aus/rhel8/8.6/x86_64/appstream/os',
        'content/aus/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/aus/rhel8/8.6/x86_64/baseos/debug',
        'content/aus/rhel8/8.6/x86_64/baseos/os',
        'content/aus/rhel8/8.6/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.6/ppc64le/appstream/debug',
        'content/e4s/rhel8/8.6/ppc64le/appstream/os',
        'content/e4s/rhel8/8.6/ppc64le/appstream/source/SRPMS',
        'content/e4s/rhel8/8.6/ppc64le/baseos/debug',
        'content/e4s/rhel8/8.6/ppc64le/baseos/os',
        'content/e4s/rhel8/8.6/ppc64le/baseos/source/SRPMS',
        'content/e4s/rhel8/8.6/ppc64le/highavailability/debug',
        'content/e4s/rhel8/8.6/ppc64le/highavailability/os',
        'content/e4s/rhel8/8.6/ppc64le/highavailability/source/SRPMS',
        'content/e4s/rhel8/8.6/ppc64le/sap-solutions/debug',
        'content/e4s/rhel8/8.6/ppc64le/sap-solutions/os',
        'content/e4s/rhel8/8.6/ppc64le/sap-solutions/source/SRPMS',
        'content/e4s/rhel8/8.6/ppc64le/sap/debug',
        'content/e4s/rhel8/8.6/ppc64le/sap/os',
        'content/e4s/rhel8/8.6/ppc64le/sap/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/appstream/debug',
        'content/e4s/rhel8/8.6/x86_64/appstream/os',
        'content/e4s/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/baseos/debug',
        'content/e4s/rhel8/8.6/x86_64/baseos/os',
        'content/e4s/rhel8/8.6/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/highavailability/debug',
        'content/e4s/rhel8/8.6/x86_64/highavailability/os',
        'content/e4s/rhel8/8.6/x86_64/highavailability/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/sap-solutions/debug',
        'content/e4s/rhel8/8.6/x86_64/sap-solutions/os',
        'content/e4s/rhel8/8.6/x86_64/sap-solutions/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/sap/debug',
        'content/e4s/rhel8/8.6/x86_64/sap/os',
        'content/e4s/rhel8/8.6/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/appstream/debug',
        'content/eus/rhel8/8.6/aarch64/appstream/os',
        'content/eus/rhel8/8.6/aarch64/appstream/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/baseos/debug',
        'content/eus/rhel8/8.6/aarch64/baseos/os',
        'content/eus/rhel8/8.6/aarch64/baseos/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/codeready-builder/debug',
        'content/eus/rhel8/8.6/aarch64/codeready-builder/os',
        'content/eus/rhel8/8.6/aarch64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/highavailability/debug',
        'content/eus/rhel8/8.6/aarch64/highavailability/os',
        'content/eus/rhel8/8.6/aarch64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/supplementary/debug',
        'content/eus/rhel8/8.6/aarch64/supplementary/os',
        'content/eus/rhel8/8.6/aarch64/supplementary/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/appstream/debug',
        'content/eus/rhel8/8.6/ppc64le/appstream/os',
        'content/eus/rhel8/8.6/ppc64le/appstream/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/baseos/debug',
        'content/eus/rhel8/8.6/ppc64le/baseos/os',
        'content/eus/rhel8/8.6/ppc64le/baseos/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/codeready-builder/debug',
        'content/eus/rhel8/8.6/ppc64le/codeready-builder/os',
        'content/eus/rhel8/8.6/ppc64le/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/highavailability/debug',
        'content/eus/rhel8/8.6/ppc64le/highavailability/os',
        'content/eus/rhel8/8.6/ppc64le/highavailability/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/resilientstorage/debug',
        'content/eus/rhel8/8.6/ppc64le/resilientstorage/os',
        'content/eus/rhel8/8.6/ppc64le/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/sap-solutions/debug',
        'content/eus/rhel8/8.6/ppc64le/sap-solutions/os',
        'content/eus/rhel8/8.6/ppc64le/sap-solutions/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/sap/debug',
        'content/eus/rhel8/8.6/ppc64le/sap/os',
        'content/eus/rhel8/8.6/ppc64le/sap/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/supplementary/debug',
        'content/eus/rhel8/8.6/ppc64le/supplementary/os',
        'content/eus/rhel8/8.6/ppc64le/supplementary/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/appstream/debug',
        'content/eus/rhel8/8.6/s390x/appstream/os',
        'content/eus/rhel8/8.6/s390x/appstream/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/baseos/debug',
        'content/eus/rhel8/8.6/s390x/baseos/os',
        'content/eus/rhel8/8.6/s390x/baseos/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/codeready-builder/debug',
        'content/eus/rhel8/8.6/s390x/codeready-builder/os',
        'content/eus/rhel8/8.6/s390x/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/highavailability/debug',
        'content/eus/rhel8/8.6/s390x/highavailability/os',
        'content/eus/rhel8/8.6/s390x/highavailability/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/resilientstorage/debug',
        'content/eus/rhel8/8.6/s390x/resilientstorage/os',
        'content/eus/rhel8/8.6/s390x/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/sap/debug',
        'content/eus/rhel8/8.6/s390x/sap/os',
        'content/eus/rhel8/8.6/s390x/sap/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/supplementary/debug',
        'content/eus/rhel8/8.6/s390x/supplementary/os',
        'content/eus/rhel8/8.6/s390x/supplementary/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/appstream/debug',
        'content/eus/rhel8/8.6/x86_64/appstream/os',
        'content/eus/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/baseos/debug',
        'content/eus/rhel8/8.6/x86_64/baseos/os',
        'content/eus/rhel8/8.6/x86_64/baseos/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/codeready-builder/debug',
        'content/eus/rhel8/8.6/x86_64/codeready-builder/os',
        'content/eus/rhel8/8.6/x86_64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/highavailability/debug',
        'content/eus/rhel8/8.6/x86_64/highavailability/os',
        'content/eus/rhel8/8.6/x86_64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/resilientstorage/debug',
        'content/eus/rhel8/8.6/x86_64/resilientstorage/os',
        'content/eus/rhel8/8.6/x86_64/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/sap-solutions/debug',
        'content/eus/rhel8/8.6/x86_64/sap-solutions/os',
        'content/eus/rhel8/8.6/x86_64/sap-solutions/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/sap/debug',
        'content/eus/rhel8/8.6/x86_64/sap/os',
        'content/eus/rhel8/8.6/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/supplementary/debug',
        'content/eus/rhel8/8.6/x86_64/supplementary/os',
        'content/eus/rhel8/8.6/x86_64/supplementary/source/SRPMS',
        'content/tus/rhel8/8.6/x86_64/appstream/debug',
        'content/tus/rhel8/8.6/x86_64/appstream/os',
        'content/tus/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/tus/rhel8/8.6/x86_64/baseos/debug',
        'content/tus/rhel8/8.6/x86_64/baseos/os',
        'content/tus/rhel8/8.6/x86_64/baseos/source/SRPMS',
        'content/tus/rhel8/8.6/x86_64/highavailability/debug',
        'content/tus/rhel8/8.6/x86_64/highavailability/os',
        'content/tus/rhel8/8.6/x86_64/highavailability/source/SRPMS',
        'content/tus/rhel8/8.6/x86_64/rt/os',
        'content/tus/rhel8/8.6/x86_64/rt/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'apcu-panel-5.1.17-1.module+el8.1.0+3189+a1bff096', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libzip-1.5.2-1.module+el8.1.0+3189+a1bff096', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libzip-devel-1.5.2-1.module+el8.1.0+3189+a1bff096', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libzip-tools-1.5.2-1.module+el8.1.0+3189+a1bff096', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-bcmath-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-cli-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-common-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-dba-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-dbg-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-devel-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-embedded-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-enchant-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-fpm-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-gd-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-gmp-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-intl-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-json-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-ldap-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-mbstring-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-mysqlnd-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-odbc-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-opcache-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pdo-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pear-1.10.9-1.module+el8.1.0+3189+a1bff096', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'php-pecl-apcu-5.1.17-1.module+el8.1.0+3189+a1bff096', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pecl-apcu-devel-5.1.17-1.module+el8.1.0+3189+a1bff096', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pecl-rrd-2.0.1-1.module+el8.2.0+4968+1d5097db', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pecl-xdebug-2.8.0-1.module+el8.2.0+4968+1d5097db', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pecl-zip-1.15.4-1.module+el8.1.0+3189+a1bff096', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pgsql-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-process-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-recode-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-snmp-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-soap-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-xml-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-xmlrpc-7.3.20-1.module+el8.2.0+7373+b272fdef', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE}
      ]
    },
    {
      'repo_relative_urls': [
        'content/dist/rhel8/8/aarch64/appstream/debug',
        'content/dist/rhel8/8/aarch64/appstream/os',
        'content/dist/rhel8/8/aarch64/appstream/source/SRPMS',
        'content/dist/rhel8/8/aarch64/baseos/debug',
        'content/dist/rhel8/8/aarch64/baseos/os',
        'content/dist/rhel8/8/aarch64/baseos/source/SRPMS',
        'content/dist/rhel8/8/aarch64/codeready-builder/debug',
        'content/dist/rhel8/8/aarch64/codeready-builder/os',
        'content/dist/rhel8/8/aarch64/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8/aarch64/highavailability/debug',
        'content/dist/rhel8/8/aarch64/highavailability/os',
        'content/dist/rhel8/8/aarch64/highavailability/source/SRPMS',
        'content/dist/rhel8/8/aarch64/supplementary/debug',
        'content/dist/rhel8/8/aarch64/supplementary/os',
        'content/dist/rhel8/8/aarch64/supplementary/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/appstream/debug',
        'content/dist/rhel8/8/ppc64le/appstream/os',
        'content/dist/rhel8/8/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/baseos/debug',
        'content/dist/rhel8/8/ppc64le/baseos/os',
        'content/dist/rhel8/8/ppc64le/baseos/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/codeready-builder/debug',
        'content/dist/rhel8/8/ppc64le/codeready-builder/os',
        'content/dist/rhel8/8/ppc64le/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/highavailability/debug',
        'content/dist/rhel8/8/ppc64le/highavailability/os',
        'content/dist/rhel8/8/ppc64le/highavailability/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/resilientstorage/debug',
        'content/dist/rhel8/8/ppc64le/resilientstorage/os',
        'content/dist/rhel8/8/ppc64le/resilientstorage/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/sap-solutions/debug',
        'content/dist/rhel8/8/ppc64le/sap-solutions/os',
        'content/dist/rhel8/8/ppc64le/sap-solutions/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/sap/debug',
        'content/dist/rhel8/8/ppc64le/sap/os',
        'content/dist/rhel8/8/ppc64le/sap/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/supplementary/debug',
        'content/dist/rhel8/8/ppc64le/supplementary/os',
        'content/dist/rhel8/8/ppc64le/supplementary/source/SRPMS',
        'content/dist/rhel8/8/s390x/appstream/debug',
        'content/dist/rhel8/8/s390x/appstream/os',
        'content/dist/rhel8/8/s390x/appstream/source/SRPMS',
        'content/dist/rhel8/8/s390x/baseos/debug',
        'content/dist/rhel8/8/s390x/baseos/os',
        'content/dist/rhel8/8/s390x/baseos/source/SRPMS',
        'content/dist/rhel8/8/s390x/codeready-builder/debug',
        'content/dist/rhel8/8/s390x/codeready-builder/os',
        'content/dist/rhel8/8/s390x/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8/s390x/highavailability/debug',
        'content/dist/rhel8/8/s390x/highavailability/os',
        'content/dist/rhel8/8/s390x/highavailability/source/SRPMS',
        'content/dist/rhel8/8/s390x/resilientstorage/debug',
        'content/dist/rhel8/8/s390x/resilientstorage/os',
        'content/dist/rhel8/8/s390x/resilientstorage/source/SRPMS',
        'content/dist/rhel8/8/s390x/sap/debug',
        'content/dist/rhel8/8/s390x/sap/os',
        'content/dist/rhel8/8/s390x/sap/source/SRPMS',
        'content/dist/rhel8/8/s390x/supplementary/debug',
        'content/dist/rhel8/8/s390x/supplementary/os',
        'content/dist/rhel8/8/s390x/supplementary/source/SRPMS',
        'content/dist/rhel8/8/x86_64/appstream/debug',
        'content/dist/rhel8/8/x86_64/appstream/os',
        'content/dist/rhel8/8/x86_64/appstream/source/SRPMS',
        'content/dist/rhel8/8/x86_64/baseos/debug',
        'content/dist/rhel8/8/x86_64/baseos/os',
        'content/dist/rhel8/8/x86_64/baseos/source/SRPMS',
        'content/dist/rhel8/8/x86_64/codeready-builder/debug',
        'content/dist/rhel8/8/x86_64/codeready-builder/os',
        'content/dist/rhel8/8/x86_64/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8/x86_64/highavailability/debug',
        'content/dist/rhel8/8/x86_64/highavailability/os',
        'content/dist/rhel8/8/x86_64/highavailability/source/SRPMS',
        'content/dist/rhel8/8/x86_64/nfv/debug',
        'content/dist/rhel8/8/x86_64/nfv/os',
        'content/dist/rhel8/8/x86_64/nfv/source/SRPMS',
        'content/dist/rhel8/8/x86_64/resilientstorage/debug',
        'content/dist/rhel8/8/x86_64/resilientstorage/os',
        'content/dist/rhel8/8/x86_64/resilientstorage/source/SRPMS',
        'content/dist/rhel8/8/x86_64/rt/debug',
        'content/dist/rhel8/8/x86_64/rt/os',
        'content/dist/rhel8/8/x86_64/rt/source/SRPMS',
        'content/dist/rhel8/8/x86_64/sap-solutions/debug',
        'content/dist/rhel8/8/x86_64/sap-solutions/os',
        'content/dist/rhel8/8/x86_64/sap-solutions/source/SRPMS',
        'content/dist/rhel8/8/x86_64/sap/debug',
        'content/dist/rhel8/8/x86_64/sap/os',
        'content/dist/rhel8/8/x86_64/sap/source/SRPMS',
        'content/dist/rhel8/8/x86_64/supplementary/debug',
        'content/dist/rhel8/8/x86_64/supplementary/os',
        'content/dist/rhel8/8/x86_64/supplementary/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'apcu-panel-5.1.17-1.module+el8.1.0+3189+a1bff096', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libzip-1.5.2-1.module+el8.1.0+3189+a1bff096', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libzip-devel-1.5.2-1.module+el8.1.0+3189+a1bff096', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libzip-tools-1.5.2-1.module+el8.1.0+3189+a1bff096', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-7.3.20-1.module+el8.2.0+7373+b272fdef', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-bcmath-7.3.20-1.module+el8.2.0+7373+b272fdef', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-cli-7.3.20-1.module+el8.2.0+7373+b272fdef', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-common-7.3.20-1.module+el8.2.0+7373+b272fdef', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-dba-7.3.20-1.module+el8.2.0+7373+b272fdef', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-dbg-7.3.20-1.module+el8.2.0+7373+b272fdef', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-devel-7.3.20-1.module+el8.2.0+7373+b272fdef', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-embedded-7.3.20-1.module+el8.2.0+7373+b272fdef', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-enchant-7.3.20-1.module+el8.2.0+7373+b272fdef', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-fpm-7.3.20-1.module+el8.2.0+7373+b272fdef', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-gd-7.3.20-1.module+el8.2.0+7373+b272fdef', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-gmp-7.3.20-1.module+el8.2.0+7373+b272fdef', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-intl-7.3.20-1.module+el8.2.0+7373+b272fdef', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-json-7.3.20-1.module+el8.2.0+7373+b272fdef', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-ldap-7.3.20-1.module+el8.2.0+7373+b272fdef', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-mbstring-7.3.20-1.module+el8.2.0+7373+b272fdef', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-mysqlnd-7.3.20-1.module+el8.2.0+7373+b272fdef', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-odbc-7.3.20-1.module+el8.2.0+7373+b272fdef', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-opcache-7.3.20-1.module+el8.2.0+7373+b272fdef', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pdo-7.3.20-1.module+el8.2.0+7373+b272fdef', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pear-1.10.9-1.module+el8.1.0+3189+a1bff096', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'php-pecl-apcu-5.1.17-1.module+el8.1.0+3189+a1bff096', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pecl-apcu-devel-5.1.17-1.module+el8.1.0+3189+a1bff096', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pecl-rrd-2.0.1-1.module+el8.2.0+4968+1d5097db', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pecl-xdebug-2.8.0-1.module+el8.2.0+4968+1d5097db', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pecl-zip-1.15.4-1.module+el8.1.0+3189+a1bff096', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pgsql-7.3.20-1.module+el8.2.0+7373+b272fdef', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-process-7.3.20-1.module+el8.2.0+7373+b272fdef', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-recode-7.3.20-1.module+el8.2.0+7373+b272fdef', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-snmp-7.3.20-1.module+el8.2.0+7373+b272fdef', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-soap-7.3.20-1.module+el8.2.0+7373+b272fdef', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-xml-7.3.20-1.module+el8.2.0+7373+b272fdef', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-xmlrpc-7.3.20-1.module+el8.2.0+7373+b272fdef', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE}
      ]
    }
  ]
};

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:appstreams, appstreams:TRUE);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var module_ver = get_kb_item('Host/RedHat/appstream/php');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module php:7.3');
if ('7.3' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module php:' + module_ver);

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var module_array ( appstreams[module] ) {
      var repo_relative_urls = NULL;
      if (!empty_or_null(module_array['repo_relative_urls'])) repo_relative_urls = module_array['repo_relative_urls'];
      var enterprise_linux_flag = rhel_repo_urls_has_content_dist_rhel(repo_urls:repo_relative_urls);
      foreach var package_array ( module_array['pkgs'] ) {
        var reference = NULL;
        var _release = NULL;
        var sp = NULL;
        var _cpu = NULL;
        var el_string = NULL;
        var rpm_spec_vers_cmp = NULL;
        var epoch = NULL;
        var allowmaj = NULL;
        var exists_check = NULL;
        if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
        if (!empty_or_null(package_array['release'])) _release = 'RHEL' + package_array['release'];
        if (!empty_or_null(package_array['sp']) && !enterprise_linux_flag) sp = package_array['sp'];
        if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
        if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
        if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
        if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
        if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
        if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
        if (reference &&
            _release &&
            rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
            (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
            rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module php:7.3');

if (flag)
{
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apcu-panel / libzip / libzip-devel / libzip-tools / php / php-bcmath / etc');
}
