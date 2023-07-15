#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:2162. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(175443);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_cve_id("CVE-2022-3165", "CVE-2022-4172");
  script_xref(name:"RHSA", value:"2023:2162");

  script_name(english:"RHEL 9 : qemu-kvm (RHSA-2023:2162)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:2162 advisory.

  - An integer underflow issue was found in the QEMU VNC server while processing ClientCutText messages in the
    extended format. A malicious client could use this flaw to make QEMU unresponsive by sending a specially
    crafted payload message, resulting in a denial of service. (CVE-2022-3165)

  - An integer overflow and buffer overflow issues were found in the ACPI Error Record Serialization Table
    (ERST) device of QEMU in the read_erst_record() and write_erst_record() functions. Both issues may allow
    the guest to overrun the host buffer allocated for the ERST memory device. A malicious guest could use
    these flaws to crash the QEMU process on the host. (CVE-2022-4172)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-3165");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-4172");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:2162");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3165");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-4172");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(120, 190, 191, 400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:9.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-audio-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-device-display-virtio-gpu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-device-display-virtio-gpu-ccw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-device-display-virtio-gpu-pci");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-device-display-virtio-vga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-device-usb-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-device-usb-redirect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-ui-egl-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-ui-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-pr-helper");
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
      {'reference':'qemu-guest-agent-7.2.0-14.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-img-7.2.0-14.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-7.2.0-14.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-7.2.0-14.el9_2', 'sp':'2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-7.2.0-14.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-audio-pa-7.2.0-14.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-audio-pa-7.2.0-14.el9_2', 'sp':'2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-audio-pa-7.2.0-14.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-block-curl-7.2.0-14.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-block-curl-7.2.0-14.el9_2', 'sp':'2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-block-curl-7.2.0-14.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-block-rbd-7.2.0-14.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-block-rbd-7.2.0-14.el9_2', 'sp':'2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-block-rbd-7.2.0-14.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-common-7.2.0-14.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-common-7.2.0-14.el9_2', 'sp':'2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-common-7.2.0-14.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-core-7.2.0-14.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-core-7.2.0-14.el9_2', 'sp':'2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-core-7.2.0-14.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-display-virtio-gpu-7.2.0-14.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-display-virtio-gpu-7.2.0-14.el9_2', 'sp':'2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-display-virtio-gpu-7.2.0-14.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-display-virtio-gpu-ccw-7.2.0-14.el9_2', 'sp':'2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-display-virtio-gpu-pci-7.2.0-14.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-display-virtio-gpu-pci-7.2.0-14.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-display-virtio-vga-7.2.0-14.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-usb-host-7.2.0-14.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-usb-host-7.2.0-14.el9_2', 'sp':'2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-usb-host-7.2.0-14.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-usb-redirect-7.2.0-14.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-docs-7.2.0-14.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-docs-7.2.0-14.el9_2', 'sp':'2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-docs-7.2.0-14.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-tools-7.2.0-14.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-tools-7.2.0-14.el9_2', 'sp':'2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-tools-7.2.0-14.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-ui-egl-headless-7.2.0-14.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-ui-opengl-7.2.0-14.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-pr-helper-7.2.0-14.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-pr-helper-7.2.0-14.el9_2', 'sp':'2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-pr-helper-7.2.0-14.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'}
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
      {'reference':'qemu-guest-agent-7.2.0-14.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-img-7.2.0-14.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-7.2.0-14.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-7.2.0-14.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-7.2.0-14.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-audio-pa-7.2.0-14.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-audio-pa-7.2.0-14.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-audio-pa-7.2.0-14.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-block-curl-7.2.0-14.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-block-curl-7.2.0-14.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-block-curl-7.2.0-14.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-block-rbd-7.2.0-14.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-block-rbd-7.2.0-14.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-block-rbd-7.2.0-14.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-common-7.2.0-14.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-common-7.2.0-14.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-common-7.2.0-14.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-core-7.2.0-14.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-core-7.2.0-14.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-core-7.2.0-14.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-display-virtio-gpu-7.2.0-14.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-display-virtio-gpu-7.2.0-14.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-display-virtio-gpu-7.2.0-14.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-display-virtio-gpu-ccw-7.2.0-14.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-display-virtio-gpu-pci-7.2.0-14.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-display-virtio-gpu-pci-7.2.0-14.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-display-virtio-vga-7.2.0-14.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-usb-host-7.2.0-14.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-usb-host-7.2.0-14.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-usb-host-7.2.0-14.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-usb-redirect-7.2.0-14.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-docs-7.2.0-14.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-docs-7.2.0-14.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-docs-7.2.0-14.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-tools-7.2.0-14.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-tools-7.2.0-14.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-tools-7.2.0-14.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-ui-egl-headless-7.2.0-14.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-ui-opengl-7.2.0-14.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-pr-helper-7.2.0-14.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-pr-helper-7.2.0-14.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-pr-helper-7.2.0-14.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'}
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
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qemu-guest-agent / qemu-img / qemu-kvm / qemu-kvm-audio-pa / etc');
}
