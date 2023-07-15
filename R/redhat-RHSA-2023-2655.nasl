#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:2655. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(175489);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_cve_id(
    "CVE-2022-4904",
    "CVE-2022-25881",
    "CVE-2023-23918",
    "CVE-2023-23920",
    "CVE-2023-23936",
    "CVE-2023-24807"
  );
  script_xref(name:"RHSA", value:"2023:2655");

  script_name(english:"RHEL 9 : nodejs and nodejs-nodemon (RHSA-2023:2655)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:2655 advisory.

  - This affects versions of the package http-cache-semantics before 4.1.1. The issue can be exploited via
    malicious request header values sent to a server, when that server reads the cache policy from the request
    using this library. (CVE-2022-25881)

  - A flaw was found in the c-ares package. The ares_set_sortlist is missing checks about the validity of the
    input string, which allows a possible arbitrary length stack overflow. This issue may cause a denial of
    service or a limited impact on confidentiality and integrity. (CVE-2022-4904)

  - A privilege escalation vulnerability exists in Node.js <19.6.1, <18.14.1, <16.19.1 and <14.21.3 that made
    it possible to bypass the experimental Permissions (https://nodejs.org/api/permissions.html) feature in
    Node.js and access non authorized modules by using process.mainModule.require(). This only affects users
    who had enabled the experimental permissions option with --experimental-policy. (CVE-2023-23918)

  - An untrusted search path vulnerability exists in Node.js. <19.6.1, <18.14.1, <16.19.1, and <14.21.3 that
    could allow an attacker to search and potentially load ICU data when running with elevated privileges.
    (CVE-2023-23920)

  - Undici is an HTTP/1.1 client for Node.js. Starting with version 2.0.0 and prior to version 5.19.1, the
    undici library does not protect `host` HTTP header from CRLF injection vulnerabilities. This issue is
    patched in Undici v5.19.1. As a workaround, sanitize the `headers.host` string before passing to undici.
    (CVE-2023-23936)

  - Undici is an HTTP/1.1 client for Node.js. Prior to version 5.19.1, the `Headers.set()` and
    `Headers.append()` methods are vulnerable to Regular Expression Denial of Service (ReDoS) attacks when
    untrusted values are passed into the functions. This is due to the inefficient regular expression used to
    normalize the values in the `headerValueNormalize()` utility function. This vulnerability was patched in
    v5.19.1. No known workarounds are available. (CVE-2023-24807)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-4904");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-25881");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-23918");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-23920");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-23936");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-24807");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:2655");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-4904");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 93, 119, 426, 863, 1333);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:9.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:9.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:9.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-full-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:npm");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '9')) audit(AUDIT_OS_NOT, 'Red Hat 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel9/9.2/x86_64/appstream/debug',
      'content/aus/rhel9/9.2/x86_64/appstream/os',
      'content/aus/rhel9/9.2/x86_64/appstream/source/SRPMS',
      'content/aus/rhel9/9.2/x86_64/baseos/debug',
      'content/aus/rhel9/9.2/x86_64/baseos/os',
      'content/aus/rhel9/9.2/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel9/9.2/aarch64/appstream/debug',
      'content/e4s/rhel9/9.2/aarch64/appstream/os',
      'content/e4s/rhel9/9.2/aarch64/appstream/source/SRPMS',
      'content/e4s/rhel9/9.2/aarch64/baseos/debug',
      'content/e4s/rhel9/9.2/aarch64/baseos/os',
      'content/e4s/rhel9/9.2/aarch64/baseos/source/SRPMS',
      'content/e4s/rhel9/9.2/aarch64/highavailability/debug',
      'content/e4s/rhel9/9.2/aarch64/highavailability/os',
      'content/e4s/rhel9/9.2/aarch64/highavailability/source/SRPMS',
      'content/e4s/rhel9/9.2/ppc64le/appstream/debug',
      'content/e4s/rhel9/9.2/ppc64le/appstream/os',
      'content/e4s/rhel9/9.2/ppc64le/appstream/source/SRPMS',
      'content/e4s/rhel9/9.2/ppc64le/baseos/debug',
      'content/e4s/rhel9/9.2/ppc64le/baseos/os',
      'content/e4s/rhel9/9.2/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel9/9.2/ppc64le/highavailability/debug',
      'content/e4s/rhel9/9.2/ppc64le/highavailability/os',
      'content/e4s/rhel9/9.2/ppc64le/highavailability/source/SRPMS',
      'content/e4s/rhel9/9.2/ppc64le/resilientstorage/debug',
      'content/e4s/rhel9/9.2/ppc64le/resilientstorage/os',
      'content/e4s/rhel9/9.2/ppc64le/resilientstorage/source/SRPMS',
      'content/e4s/rhel9/9.2/ppc64le/sap-solutions/debug',
      'content/e4s/rhel9/9.2/ppc64le/sap-solutions/os',
      'content/e4s/rhel9/9.2/ppc64le/sap-solutions/source/SRPMS',
      'content/e4s/rhel9/9.2/ppc64le/sap/debug',
      'content/e4s/rhel9/9.2/ppc64le/sap/os',
      'content/e4s/rhel9/9.2/ppc64le/sap/source/SRPMS',
      'content/e4s/rhel9/9.2/s390x/appstream/debug',
      'content/e4s/rhel9/9.2/s390x/appstream/os',
      'content/e4s/rhel9/9.2/s390x/appstream/source/SRPMS',
      'content/e4s/rhel9/9.2/s390x/baseos/debug',
      'content/e4s/rhel9/9.2/s390x/baseos/os',
      'content/e4s/rhel9/9.2/s390x/baseos/source/SRPMS',
      'content/e4s/rhel9/9.2/s390x/highavailability/debug',
      'content/e4s/rhel9/9.2/s390x/highavailability/os',
      'content/e4s/rhel9/9.2/s390x/highavailability/source/SRPMS',
      'content/e4s/rhel9/9.2/s390x/resilientstorage/debug',
      'content/e4s/rhel9/9.2/s390x/resilientstorage/os',
      'content/e4s/rhel9/9.2/s390x/resilientstorage/source/SRPMS',
      'content/e4s/rhel9/9.2/s390x/sap/debug',
      'content/e4s/rhel9/9.2/s390x/sap/os',
      'content/e4s/rhel9/9.2/s390x/sap/source/SRPMS',
      'content/e4s/rhel9/9.2/x86_64/appstream/debug',
      'content/e4s/rhel9/9.2/x86_64/appstream/os',
      'content/e4s/rhel9/9.2/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel9/9.2/x86_64/baseos/debug',
      'content/e4s/rhel9/9.2/x86_64/baseos/os',
      'content/e4s/rhel9/9.2/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel9/9.2/x86_64/highavailability/debug',
      'content/e4s/rhel9/9.2/x86_64/highavailability/os',
      'content/e4s/rhel9/9.2/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel9/9.2/x86_64/resilientstorage/debug',
      'content/e4s/rhel9/9.2/x86_64/resilientstorage/os',
      'content/e4s/rhel9/9.2/x86_64/resilientstorage/source/SRPMS',
      'content/e4s/rhel9/9.2/x86_64/sap-solutions/debug',
      'content/e4s/rhel9/9.2/x86_64/sap-solutions/os',
      'content/e4s/rhel9/9.2/x86_64/sap-solutions/source/SRPMS',
      'content/e4s/rhel9/9.2/x86_64/sap/debug',
      'content/e4s/rhel9/9.2/x86_64/sap/os',
      'content/e4s/rhel9/9.2/x86_64/sap/source/SRPMS',
      'content/eus/rhel9/9.2/aarch64/appstream/debug',
      'content/eus/rhel9/9.2/aarch64/appstream/os',
      'content/eus/rhel9/9.2/aarch64/appstream/source/SRPMS',
      'content/eus/rhel9/9.2/aarch64/baseos/debug',
      'content/eus/rhel9/9.2/aarch64/baseos/os',
      'content/eus/rhel9/9.2/aarch64/baseos/source/SRPMS',
      'content/eus/rhel9/9.2/aarch64/codeready-builder/debug',
      'content/eus/rhel9/9.2/aarch64/codeready-builder/os',
      'content/eus/rhel9/9.2/aarch64/codeready-builder/source/SRPMS',
      'content/eus/rhel9/9.2/aarch64/highavailability/debug',
      'content/eus/rhel9/9.2/aarch64/highavailability/os',
      'content/eus/rhel9/9.2/aarch64/highavailability/source/SRPMS',
      'content/eus/rhel9/9.2/aarch64/supplementary/debug',
      'content/eus/rhel9/9.2/aarch64/supplementary/os',
      'content/eus/rhel9/9.2/aarch64/supplementary/source/SRPMS',
      'content/eus/rhel9/9.2/ppc64le/appstream/debug',
      'content/eus/rhel9/9.2/ppc64le/appstream/os',
      'content/eus/rhel9/9.2/ppc64le/appstream/source/SRPMS',
      'content/eus/rhel9/9.2/ppc64le/baseos/debug',
      'content/eus/rhel9/9.2/ppc64le/baseos/os',
      'content/eus/rhel9/9.2/ppc64le/baseos/source/SRPMS',
      'content/eus/rhel9/9.2/ppc64le/codeready-builder/debug',
      'content/eus/rhel9/9.2/ppc64le/codeready-builder/os',
      'content/eus/rhel9/9.2/ppc64le/codeready-builder/source/SRPMS',
      'content/eus/rhel9/9.2/ppc64le/highavailability/debug',
      'content/eus/rhel9/9.2/ppc64le/highavailability/os',
      'content/eus/rhel9/9.2/ppc64le/highavailability/source/SRPMS',
      'content/eus/rhel9/9.2/ppc64le/resilientstorage/debug',
      'content/eus/rhel9/9.2/ppc64le/resilientstorage/os',
      'content/eus/rhel9/9.2/ppc64le/resilientstorage/source/SRPMS',
      'content/eus/rhel9/9.2/ppc64le/sap-solutions/debug',
      'content/eus/rhel9/9.2/ppc64le/sap-solutions/os',
      'content/eus/rhel9/9.2/ppc64le/sap-solutions/source/SRPMS',
      'content/eus/rhel9/9.2/ppc64le/sap/debug',
      'content/eus/rhel9/9.2/ppc64le/sap/os',
      'content/eus/rhel9/9.2/ppc64le/sap/source/SRPMS',
      'content/eus/rhel9/9.2/ppc64le/supplementary/debug',
      'content/eus/rhel9/9.2/ppc64le/supplementary/os',
      'content/eus/rhel9/9.2/ppc64le/supplementary/source/SRPMS',
      'content/eus/rhel9/9.2/s390x/appstream/debug',
      'content/eus/rhel9/9.2/s390x/appstream/os',
      'content/eus/rhel9/9.2/s390x/appstream/source/SRPMS',
      'content/eus/rhel9/9.2/s390x/baseos/debug',
      'content/eus/rhel9/9.2/s390x/baseos/os',
      'content/eus/rhel9/9.2/s390x/baseos/source/SRPMS',
      'content/eus/rhel9/9.2/s390x/codeready-builder/debug',
      'content/eus/rhel9/9.2/s390x/codeready-builder/os',
      'content/eus/rhel9/9.2/s390x/codeready-builder/source/SRPMS',
      'content/eus/rhel9/9.2/s390x/highavailability/debug',
      'content/eus/rhel9/9.2/s390x/highavailability/os',
      'content/eus/rhel9/9.2/s390x/highavailability/source/SRPMS',
      'content/eus/rhel9/9.2/s390x/resilientstorage/debug',
      'content/eus/rhel9/9.2/s390x/resilientstorage/os',
      'content/eus/rhel9/9.2/s390x/resilientstorage/source/SRPMS',
      'content/eus/rhel9/9.2/s390x/sap/debug',
      'content/eus/rhel9/9.2/s390x/sap/os',
      'content/eus/rhel9/9.2/s390x/sap/source/SRPMS',
      'content/eus/rhel9/9.2/s390x/supplementary/debug',
      'content/eus/rhel9/9.2/s390x/supplementary/os',
      'content/eus/rhel9/9.2/s390x/supplementary/source/SRPMS',
      'content/eus/rhel9/9.2/x86_64/appstream/debug',
      'content/eus/rhel9/9.2/x86_64/appstream/os',
      'content/eus/rhel9/9.2/x86_64/appstream/source/SRPMS',
      'content/eus/rhel9/9.2/x86_64/baseos/debug',
      'content/eus/rhel9/9.2/x86_64/baseos/os',
      'content/eus/rhel9/9.2/x86_64/baseos/source/SRPMS',
      'content/eus/rhel9/9.2/x86_64/codeready-builder/debug',
      'content/eus/rhel9/9.2/x86_64/codeready-builder/os',
      'content/eus/rhel9/9.2/x86_64/codeready-builder/source/SRPMS',
      'content/eus/rhel9/9.2/x86_64/highavailability/debug',
      'content/eus/rhel9/9.2/x86_64/highavailability/os',
      'content/eus/rhel9/9.2/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel9/9.2/x86_64/resilientstorage/debug',
      'content/eus/rhel9/9.2/x86_64/resilientstorage/os',
      'content/eus/rhel9/9.2/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel9/9.2/x86_64/sap-solutions/debug',
      'content/eus/rhel9/9.2/x86_64/sap-solutions/os',
      'content/eus/rhel9/9.2/x86_64/sap-solutions/source/SRPMS',
      'content/eus/rhel9/9.2/x86_64/sap/debug',
      'content/eus/rhel9/9.2/x86_64/sap/os',
      'content/eus/rhel9/9.2/x86_64/sap/source/SRPMS',
      'content/eus/rhel9/9.2/x86_64/supplementary/debug',
      'content/eus/rhel9/9.2/x86_64/supplementary/os',
      'content/eus/rhel9/9.2/x86_64/supplementary/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'nodejs-16.19.1-1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-docs-16.19.1-1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-full-i18n-16.19.1-1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-libs-16.19.1-1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'npm-8.19.3-1.16.19.1.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel9/9/aarch64/appstream/debug',
      'content/dist/rhel9/9/aarch64/appstream/os',
      'content/dist/rhel9/9/aarch64/appstream/source/SRPMS',
      'content/dist/rhel9/9/aarch64/baseos/debug',
      'content/dist/rhel9/9/aarch64/baseos/os',
      'content/dist/rhel9/9/aarch64/baseos/source/SRPMS',
      'content/dist/rhel9/9/aarch64/codeready-builder/debug',
      'content/dist/rhel9/9/aarch64/codeready-builder/os',
      'content/dist/rhel9/9/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9/aarch64/highavailability/debug',
      'content/dist/rhel9/9/aarch64/highavailability/os',
      'content/dist/rhel9/9/aarch64/highavailability/source/SRPMS',
      'content/dist/rhel9/9/aarch64/supplementary/debug',
      'content/dist/rhel9/9/aarch64/supplementary/os',
      'content/dist/rhel9/9/aarch64/supplementary/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/appstream/debug',
      'content/dist/rhel9/9/ppc64le/appstream/os',
      'content/dist/rhel9/9/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/baseos/debug',
      'content/dist/rhel9/9/ppc64le/baseos/os',
      'content/dist/rhel9/9/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/codeready-builder/debug',
      'content/dist/rhel9/9/ppc64le/codeready-builder/os',
      'content/dist/rhel9/9/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/highavailability/debug',
      'content/dist/rhel9/9/ppc64le/highavailability/os',
      'content/dist/rhel9/9/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/resilientstorage/debug',
      'content/dist/rhel9/9/ppc64le/resilientstorage/os',
      'content/dist/rhel9/9/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/sap-solutions/debug',
      'content/dist/rhel9/9/ppc64le/sap-solutions/os',
      'content/dist/rhel9/9/ppc64le/sap-solutions/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/sap/debug',
      'content/dist/rhel9/9/ppc64le/sap/os',
      'content/dist/rhel9/9/ppc64le/sap/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/supplementary/debug',
      'content/dist/rhel9/9/ppc64le/supplementary/os',
      'content/dist/rhel9/9/ppc64le/supplementary/source/SRPMS',
      'content/dist/rhel9/9/s390x/appstream/debug',
      'content/dist/rhel9/9/s390x/appstream/os',
      'content/dist/rhel9/9/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9/s390x/baseos/debug',
      'content/dist/rhel9/9/s390x/baseos/os',
      'content/dist/rhel9/9/s390x/baseos/source/SRPMS',
      'content/dist/rhel9/9/s390x/codeready-builder/debug',
      'content/dist/rhel9/9/s390x/codeready-builder/os',
      'content/dist/rhel9/9/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9/s390x/highavailability/debug',
      'content/dist/rhel9/9/s390x/highavailability/os',
      'content/dist/rhel9/9/s390x/highavailability/source/SRPMS',
      'content/dist/rhel9/9/s390x/resilientstorage/debug',
      'content/dist/rhel9/9/s390x/resilientstorage/os',
      'content/dist/rhel9/9/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9/s390x/sap/debug',
      'content/dist/rhel9/9/s390x/sap/os',
      'content/dist/rhel9/9/s390x/sap/source/SRPMS',
      'content/dist/rhel9/9/s390x/supplementary/debug',
      'content/dist/rhel9/9/s390x/supplementary/os',
      'content/dist/rhel9/9/s390x/supplementary/source/SRPMS',
      'content/dist/rhel9/9/x86_64/appstream/debug',
      'content/dist/rhel9/9/x86_64/appstream/os',
      'content/dist/rhel9/9/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9/x86_64/baseos/debug',
      'content/dist/rhel9/9/x86_64/baseos/os',
      'content/dist/rhel9/9/x86_64/baseos/source/SRPMS',
      'content/dist/rhel9/9/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9/x86_64/codeready-builder/os',
      'content/dist/rhel9/9/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9/x86_64/highavailability/debug',
      'content/dist/rhel9/9/x86_64/highavailability/os',
      'content/dist/rhel9/9/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel9/9/x86_64/nfv/debug',
      'content/dist/rhel9/9/x86_64/nfv/os',
      'content/dist/rhel9/9/x86_64/nfv/source/SRPMS',
      'content/dist/rhel9/9/x86_64/resilientstorage/debug',
      'content/dist/rhel9/9/x86_64/resilientstorage/os',
      'content/dist/rhel9/9/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9/x86_64/rt/debug',
      'content/dist/rhel9/9/x86_64/rt/os',
      'content/dist/rhel9/9/x86_64/rt/source/SRPMS',
      'content/dist/rhel9/9/x86_64/sap-solutions/debug',
      'content/dist/rhel9/9/x86_64/sap-solutions/os',
      'content/dist/rhel9/9/x86_64/sap-solutions/source/SRPMS',
      'content/dist/rhel9/9/x86_64/sap/debug',
      'content/dist/rhel9/9/x86_64/sap/os',
      'content/dist/rhel9/9/x86_64/sap/source/SRPMS',
      'content/dist/rhel9/9/x86_64/supplementary/debug',
      'content/dist/rhel9/9/x86_64/supplementary/os',
      'content/dist/rhel9/9/x86_64/supplementary/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'nodejs-16.19.1-1.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-docs-16.19.1-1.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-full-i18n-16.19.1-1.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-libs-16.19.1-1.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'npm-8.19.3-1.16.19.1.1.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  var enterprise_linux_flag = rhel_repo_urls_has_content_dist_rhel(repo_urls:repo_relative_urls);
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp']) && !enterprise_linux_flag) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get() + redhat_report_package_caveat();
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nodejs / nodejs-docs / nodejs-full-i18n / nodejs-libs / npm');
}
