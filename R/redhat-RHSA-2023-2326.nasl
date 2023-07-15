#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:2326. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(175472);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_cve_id(
    "CVE-2022-39282",
    "CVE-2022-39283",
    "CVE-2022-39316",
    "CVE-2022-39317",
    "CVE-2022-39318",
    "CVE-2022-39319",
    "CVE-2022-39320",
    "CVE-2022-39347",
    "CVE-2022-41877"
  );
  script_xref(name:"RHSA", value:"2023:2326");

  script_name(english:"RHEL 9 : freerdp (RHSA-2023:2326)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:2326 advisory.

  - FreeRDP is a free remote desktop protocol library and clients. FreeRDP based clients on unix systems using
    `/parallel` command line switch might read uninitialized data and send it to the server the client is
    currently connected to. FreeRDP based server implementations are not affected. Please upgrade to 2.8.1
    where this issue is patched. If unable to upgrade, do not use parallel port redirection (`/parallel`
    command line switch) as a workaround. (CVE-2022-39282)

  - FreeRDP is a free remote desktop protocol library and clients. All FreeRDP based clients when using the
    `/video` command line switch might read uninitialized data, decode it as audio/video and display the
    result. FreeRDP based server implementations are not affected. This issue has been patched in version
    2.8.1. If you cannot upgrade do not use the `/video` switch. (CVE-2022-39283)

  - FreeRDP is a free remote desktop protocol library and clients. In affected versions there is an out of
    bound read in ZGFX decoder component of FreeRDP. A malicious server can trick a FreeRDP based client to
    read out of bound data and try to decode it likely resulting in a crash. This issue has been addressed in
    the 2.9.0 release. Users are advised to upgrade. (CVE-2022-39316)

  - FreeRDP is a free remote desktop protocol library and clients. Affected versions of FreeRDP are missing a
    range check for input offset index in ZGFX decoder. A malicious server can trick a FreeRDP based client to
    read out of bound data and try to decode it. This issue has been addressed in version 2.9.0. There are no
    known workarounds for this issue. (CVE-2022-39317)

  - FreeRDP is a free remote desktop protocol library and clients. Affected versions of FreeRDP are missing
    input validation in `urbdrc` channel. A malicious server can trick a FreeRDP based client to crash with
    division by zero. This issue has been addressed in version 2.9.0. All users are advised to upgrade. Users
    unable to upgrade should not use the `/usb` redirection switch. (CVE-2022-39318)

  - FreeRDP is a free remote desktop protocol library and clients. Affected versions of FreeRDP are missing
    input length validation in the `urbdrc` channel. A malicious server can trick a FreeRDP based client to
    read out of bound data and send it back to the server. This issue has been addressed in version 2.9.0 and
    all users are advised to upgrade. Users unable to upgrade should not use the `/usb` redirection switch.
    (CVE-2022-39319)

  - FreeRDP is a free remote desktop protocol library and clients. Affected versions of FreeRDP may attempt
    integer addition on too narrow types leads to allocation of a buffer too small holding the data written. A
    malicious server can trick a FreeRDP based client to read out of bound data and send it back to the
    server. This issue has been addressed in version 2.9.0 and all users are advised to upgrade. Users unable
    to upgrade should not use the `/usb` redirection switch. (CVE-2022-39320)

  - FreeRDP is a free remote desktop protocol library and clients. Affected versions of FreeRDP are missing
    path canonicalization and base path check for `drive` channel. A malicious server can trick a FreeRDP
    based client to read files outside the shared directory. This issue has been addressed in version 2.9.0
    and all users are advised to upgrade. Users unable to upgrade should not use the `/drive`, `/drives` or
    `+home-drive` redirection switch. (CVE-2022-39347)

  - FreeRDP is a free remote desktop protocol library and clients. Affected versions of FreeRDP are missing
    input length validation in `drive` channel. A malicious server can trick a FreeRDP based client to read
    out of bound data and send it back to the server. This issue has been addressed in version 2.9.0 and all
    users are advised to upgrade. Users unable to upgrade should not use the drive redirection channel -
    command line options `/drive`, `+drives` or `+home-drive`. (CVE-2022-41877)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-39282");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-39283");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-39316");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-39317");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-39318");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-39319");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-39320");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-39347");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-41877");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:2326");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-39283");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 22, 119, 125, 369, 908);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:9.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:9.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:9.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freerdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freerdp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freerdp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwinpr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwinpr-devel");
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
      {'reference':'freerdp-2.4.1-5.el9', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'freerdp-devel-2.4.1-5.el9', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'freerdp-libs-2.4.1-5.el9', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'libwinpr-2.4.1-5.el9', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'libwinpr-devel-2.4.1-5.el9', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'}
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
      {'reference':'freerdp-2.4.1-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'freerdp-devel-2.4.1-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'freerdp-libs-2.4.1-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'libwinpr-2.4.1-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'libwinpr-devel-2.4.1-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'freerdp / freerdp-devel / freerdp-libs / libwinpr / libwinpr-devel');
}
