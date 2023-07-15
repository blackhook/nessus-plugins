##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:1624. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(136057);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id(
    "CVE-2018-20783",
    "CVE-2019-9020",
    "CVE-2019-9021",
    "CVE-2019-9022",
    "CVE-2019-9023",
    "CVE-2019-9024",
    "CVE-2019-9637",
    "CVE-2019-9638",
    "CVE-2019-9639",
    "CVE-2019-9640",
    "CVE-2019-11034",
    "CVE-2019-11035",
    "CVE-2019-11036",
    "CVE-2019-11039",
    "CVE-2019-11040",
    "CVE-2019-11041",
    "CVE-2019-11042"
  );
  script_bugtraq_id(
    108177,
    107156,
    107794,
    107154,
    107379,
    108520,
    108525,
    107121
  );
  script_xref(name:"RHSA", value:"2020:1624");
  script_xref(name:"IAVB", value:"2019-B-0045-S");
  script_xref(name:"IAVA", value:"2019-A-0437-S");
  script_xref(name:"IAVB", value:"2019-B-0070-S");
  script_xref(name:"IAVB", value:"2019-B-0020-S");
  script_xref(name:"IAVB", value:"2018-B-0157-S");
  script_xref(name:"IAVB", value:"2019-B-0030-S");
  script_xref(name:"IAVB", value:"2019-B-0033-S");

  script_name(english:"RHEL 8 : php:7.2 (RHSA-2020:1624)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:1624 advisory.

  - php: Buffer over-read in PHAR reading functions (CVE-2018-20783)

  - php: Heap buffer overflow in function exif_process_IFD_TAG() (CVE-2019-11034)

  - php: Heap buffer overflow in function exif_iif_add_value() (CVE-2019-11035)

  - php: Buffer over-read in exif_process_IFD_TAG() leading to information disclosure (CVE-2019-11036)

  - php: Out-of-bounds read due to integer overflow in iconv_mime_decode_headers() (CVE-2019-11039)

  - php: Buffer over-read in exif_read_data() (CVE-2019-11040)

  - php: Heap buffer over-read in exif_scan_thumbnail() (CVE-2019-11041)

  - php: Heap buffer over-read in exif_process_user_comment() (CVE-2019-11042)

  - php: Invalid memory access in function xmlrpc_decode() (CVE-2019-9020)

  - php: Heap-based buffer over-read in PHAR reading functions (CVE-2019-9021)

  - php: memcpy with negative length via crafted DNS response (CVE-2019-9022)

  - php: Heap-based buffer over-read in mbstring regular expression functions (CVE-2019-9023)

  - php: Out-of-bounds read in base64_decode_xmlrpc in ext/xmlrpc/libxmlrpc/base64.c (CVE-2019-9024)

  - php: File rename across filesystems may allow unwanted access during processing (CVE-2019-9637)

  - php: Uninitialized read in exif_process_IFD_in_MAKERNOTE (CVE-2019-9638, CVE-2019-9639)

  - php: Invalid read in exif_process_SOFn() (CVE-2019-9640)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-20783");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-9020");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-9021");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-9022");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-9023");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-9024");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-9637");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-9638");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-9639");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-9640");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-11034");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-11035");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-11036");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-11039");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-11040");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-11041");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-11042");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:1624");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1680545");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1685123");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1685132");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1685398");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1685404");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1685412");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1688897");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1688922");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1688934");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1688939");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1702246");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1702256");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1707299");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1724152");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1724154");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1739459");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1739465");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9023");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 120, 122, 125, 190, 266, 665);

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/28");

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
  'php:7.2': [
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
        {'reference':'apcu-panel-5.1.12-2.module+el8.1.0+3202+af5476b9', 'sp':'2', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libzip-1.5.1-2.module+el8.1.0+3202+af5476b9', 'sp':'2', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libzip-devel-1.5.1-2.module+el8.1.0+3202+af5476b9', 'sp':'2', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libzip-tools-1.5.1-2.module+el8.1.0+3202+af5476b9', 'sp':'2', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-bcmath-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-cli-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-common-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-dba-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-dbg-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-devel-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-embedded-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-enchant-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-fpm-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-gd-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-gmp-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-intl-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-json-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-ldap-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-mbstring-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-mysqlnd-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-odbc-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-opcache-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pdo-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pear-1.10.5-9.module+el8.1.0+3202+af5476b9', 'sp':'2', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'php-pecl-apcu-5.1.12-2.module+el8.1.0+3202+af5476b9', 'sp':'2', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pecl-apcu-devel-5.1.12-2.module+el8.1.0+3202+af5476b9', 'sp':'2', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pecl-zip-1.15.3-1.module+el8.1.0+3186+20164e6f', 'sp':'2', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pgsql-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-process-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-recode-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-snmp-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-soap-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-xml-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-xmlrpc-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE}
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
        {'reference':'apcu-panel-5.1.12-2.module+el8.1.0+3202+af5476b9', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libzip-1.5.1-2.module+el8.1.0+3202+af5476b9', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libzip-devel-1.5.1-2.module+el8.1.0+3202+af5476b9', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libzip-tools-1.5.1-2.module+el8.1.0+3202+af5476b9', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-bcmath-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-cli-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-common-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-dba-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-dbg-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-devel-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-embedded-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-enchant-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-fpm-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-gd-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-gmp-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-intl-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-json-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-ldap-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-mbstring-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-mysqlnd-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-odbc-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-opcache-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pdo-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pear-1.10.5-9.module+el8.1.0+3202+af5476b9', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'php-pecl-apcu-5.1.12-2.module+el8.1.0+3202+af5476b9', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pecl-apcu-devel-5.1.12-2.module+el8.1.0+3202+af5476b9', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pecl-zip-1.15.3-1.module+el8.1.0+3186+20164e6f', 'sp':'4', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pgsql-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-process-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-recode-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-snmp-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-soap-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-xml-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-xmlrpc-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'4', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE}
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
        {'reference':'apcu-panel-5.1.12-2.module+el8.1.0+3202+af5476b9', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libzip-1.5.1-2.module+el8.1.0+3202+af5476b9', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libzip-devel-1.5.1-2.module+el8.1.0+3202+af5476b9', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libzip-tools-1.5.1-2.module+el8.1.0+3202+af5476b9', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-bcmath-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-cli-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-common-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-dba-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-dbg-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-devel-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-embedded-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-enchant-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-fpm-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-gd-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-gmp-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-intl-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-json-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-ldap-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-mbstring-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-mysqlnd-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-odbc-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-opcache-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pdo-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pear-1.10.5-9.module+el8.1.0+3202+af5476b9', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'php-pecl-apcu-5.1.12-2.module+el8.1.0+3202+af5476b9', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pecl-apcu-devel-5.1.12-2.module+el8.1.0+3202+af5476b9', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pecl-zip-1.15.3-1.module+el8.1.0+3186+20164e6f', 'sp':'6', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pgsql-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-process-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-recode-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-snmp-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-soap-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-xml-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-xmlrpc-7.2.24-1.module+el8.2.0+4601+7c76a223', 'sp':'6', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE}
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
        {'reference':'apcu-panel-5.1.12-2.module+el8.1.0+3202+af5476b9', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libzip-1.5.1-2.module+el8.1.0+3202+af5476b9', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libzip-devel-1.5.1-2.module+el8.1.0+3202+af5476b9', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libzip-tools-1.5.1-2.module+el8.1.0+3202+af5476b9', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-7.2.24-1.module+el8.2.0+4601+7c76a223', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-bcmath-7.2.24-1.module+el8.2.0+4601+7c76a223', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-cli-7.2.24-1.module+el8.2.0+4601+7c76a223', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-common-7.2.24-1.module+el8.2.0+4601+7c76a223', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-dba-7.2.24-1.module+el8.2.0+4601+7c76a223', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-dbg-7.2.24-1.module+el8.2.0+4601+7c76a223', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-devel-7.2.24-1.module+el8.2.0+4601+7c76a223', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-embedded-7.2.24-1.module+el8.2.0+4601+7c76a223', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-enchant-7.2.24-1.module+el8.2.0+4601+7c76a223', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-fpm-7.2.24-1.module+el8.2.0+4601+7c76a223', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-gd-7.2.24-1.module+el8.2.0+4601+7c76a223', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-gmp-7.2.24-1.module+el8.2.0+4601+7c76a223', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-intl-7.2.24-1.module+el8.2.0+4601+7c76a223', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-json-7.2.24-1.module+el8.2.0+4601+7c76a223', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-ldap-7.2.24-1.module+el8.2.0+4601+7c76a223', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-mbstring-7.2.24-1.module+el8.2.0+4601+7c76a223', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-mysqlnd-7.2.24-1.module+el8.2.0+4601+7c76a223', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-odbc-7.2.24-1.module+el8.2.0+4601+7c76a223', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-opcache-7.2.24-1.module+el8.2.0+4601+7c76a223', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pdo-7.2.24-1.module+el8.2.0+4601+7c76a223', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pear-1.10.5-9.module+el8.1.0+3202+af5476b9', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'php-pecl-apcu-5.1.12-2.module+el8.1.0+3202+af5476b9', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pecl-apcu-devel-5.1.12-2.module+el8.1.0+3202+af5476b9', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pecl-zip-1.15.3-1.module+el8.1.0+3186+20164e6f', 'release':'8', 'el_string':'el8.1.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-pgsql-7.2.24-1.module+el8.2.0+4601+7c76a223', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-process-7.2.24-1.module+el8.2.0+4601+7c76a223', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-recode-7.2.24-1.module+el8.2.0+4601+7c76a223', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-snmp-7.2.24-1.module+el8.2.0+4601+7c76a223', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-soap-7.2.24-1.module+el8.2.0+4601+7c76a223', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-xml-7.2.24-1.module+el8.2.0+4601+7c76a223', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'php-xmlrpc-7.2.24-1.module+el8.2.0+4601+7c76a223', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE}
      ]
    }
  ]
};

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:appstreams, appstreams:TRUE);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var module_ver = get_kb_item('Host/RedHat/appstream/php');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module php:7.2');
if ('7.2' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module php:' + module_ver);

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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module php:7.2');

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
