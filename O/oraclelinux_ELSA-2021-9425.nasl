#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-9425.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152618);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/17");

  script_cve_id(
    "CVE-2021-3392",
    "CVE-2021-3527",
    "CVE-2021-3544",
    "CVE-2021-3545",
    "CVE-2021-3546",
    "CVE-2021-3582",
    "CVE-2021-3607",
    "CVE-2021-3608"
  );

  script_name(english:"Oracle Linux 7 : qemu (ELSA-2021-9425)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2021-9425 advisory.

  - A use-after-free flaw was found in the MegaRAID emulator of QEMU. This issue occurs while processing SCSI
    I/O requests in the case of an error mptsas_free_request() that does not dequeue the request object 'req'
    from a pending requests queue. This flaw allows a privileged guest user to crash the QEMU process on the
    host, resulting in a denial of service. Versions between 2.10.0 and 5.2.0 are potentially affected.
    (CVE-2021-3392)

  - A flaw was found in the USB redirector device (usb-redir) of QEMU. Small USB packets are combined into a
    single, large transfer request, to reduce the overhead and improve performance. The combined size of the
    bulk transfer is used to dynamically allocate a variable length array (VLA) on the stack without proper
    validation. Since the total size is not bounded, a malicious guest could use this flaw to influence the
    array length and cause the QEMU process to perform an excessive allocation on the stack, resulting in a
    denial of service. (CVE-2021-3527)

  - Several memory leaks were found in the virtio vhost-user GPU device (vhost-user-gpu) of QEMU in versions
    up to and including 6.0. They exist in contrib/vhost-user-gpu/vhost-user-gpu.c and contrib/vhost-user-
    gpu/virgl.c due to improper release of memory (i.e., free) after effective lifetime. (CVE-2021-3544)

  - An information disclosure vulnerability was found in the virtio vhost-user GPU device (vhost-user-gpu) of
    QEMU in versions up to and including 6.0. The flaw exists in virgl_cmd_get_capset_info() in contrib/vhost-
    user-gpu/virgl.c and could occur due to the read of uninitialized memory. A malicious guest could exploit
    this issue to leak memory from the host. (CVE-2021-3545)

  - A flaw was found in vhost-user-gpu of QEMU in versions up to and including 6.0. An out-of-bounds write
    vulnerability can allow a malicious guest to crash the QEMU process on the host resulting in a denial of
    service or potentially execute arbitrary code on the host with the privileges of the QEMU process. The
    highest threat from this vulnerability is to data confidentiality and integrity as well as system
    availability. (CVE-2021-3546)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-9425.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3546");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ivshmem-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-block-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-system-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-system-aarch64-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-system-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-system-x86-core");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'ivshmem-tools-4.2.1-11.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-4.2.1-11.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-4.2.1-11.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-block-gluster-4.2.1-11.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-block-gluster-4.2.1-11.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-block-iscsi-4.2.1-11.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-block-iscsi-4.2.1-11.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-block-rbd-4.2.1-11.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-block-rbd-4.2.1-11.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-common-4.2.1-11.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-common-4.2.1-11.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-img-4.2.1-11.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-img-4.2.1-11.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-4.2.1-11.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-4.2.1-11.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-core-4.2.1-11.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-core-4.2.1-11.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-system-aarch64-4.2.1-11.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-system-aarch64-core-4.2.1-11.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-system-x86-4.2.1-11.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-system-x86-core-4.2.1-11.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release) {
    if (exists_check) {
        if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ivshmem-tools / qemu / qemu-block-gluster / etc');
}
