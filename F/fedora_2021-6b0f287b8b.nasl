##
# (C) Tenable Network Security, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2021-6b0f287b8b
#

include('compat.inc');

if (description)
{
  script_id(148796);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/19");

  script_cve_id(
    "CVE-2021-29264",
    "CVE-2021-29646",
    "CVE-2021-29647",
    "CVE-2021-29648",
    "CVE-2021-29649",
    "CVE-2021-29650"
  );
  script_xref(name:"FEDORA", value:"2021-6b0f287b8b");

  script_name(english:"Fedora 32 : kernel / kernel-headers / kernel-tools (2021-6b0f287b8b)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 32 host has packages installed that are affected by multiple vulnerabilities as referenced in the
FEDORA-2021-6b0f287b8b advisory.

  - An issue was discovered in the Linux kernel through 5.11.10. drivers/net/ethernet/freescale/gianfar.c in
    the Freescale Gianfar Ethernet driver allows attackers to cause a system crash because a negative fragment
    size is calculated in situations involving an rx queue overrun when jumbo packets are used and NAPI is
    enabled, aka CID-d8861bab48b6. (CVE-2021-29264)

  - An issue was discovered in the Linux kernel before 5.11.11. tipc_nl_retrieve_key in net/tipc/node.c does
    not properly validate certain data sizes, aka CID-0217ed2848e8. (CVE-2021-29646)

  - An issue was discovered in the Linux kernel before 5.11.11. qrtr_recvmsg in net/qrtr/qrtr.c allows
    attackers to obtain sensitive information from kernel memory because of a partially uninitialized data
    structure, aka CID-50535249f624. (CVE-2021-29647)

  - An issue was discovered in the Linux kernel before 5.11.11. The BPF subsystem does not properly consider
    that resolved_ids and resolved_sizes are intentionally uninitialized in the vmlinux BPF Type Format (BTF),
    which can cause a system crash upon an unexpected access attempt (in map_create in kernel/bpf/syscall.c or
    check_btf_info in kernel/bpf/verifier.c), aka CID-350a5c4dd245. (CVE-2021-29648)

  - An issue was discovered in the Linux kernel before 5.11.11. The user mode driver (UMD) has a
    copy_process() memory leak, related to a lack of cleanup steps in kernel/usermode_driver.c and
    kernel/bpf/preload/bpf_preload_kern.c, aka CID-f60a85cad677. (CVE-2021-29649)

  - An issue was discovered in the Linux kernel before 5.11.11. The netfilter subsystem allows attackers to
    cause a denial of service (panic) because net/netfilter/x_tables.c and include/linux/netfilter/x_tables.h
    lack a full memory barrier upon the assignment of a new table value, aka CID-175e476b8cdf.
    (CVE-2021-29650)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2021-6b0f287b8b");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel, kernel-headers and / or kernel-tools packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29647");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-tools");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/RedHat/release');
if (isnull(release) || 'Fedora' >!< release) audit(AUDIT_OS_NOT, 'Fedora');
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^32([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 32', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  cve_list = make_list('CVE-2021-29264', 'CVE-2021-29646', 'CVE-2021-29647', 'CVE-2021-29648', 'CVE-2021-29649', 'CVE-2021-29650');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for FEDORA-2021-6b0f287b8b');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

pkgs = [
    {'reference':'kernel-5.11.11-100.fc32', 'release':'FC32', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-5.11.11-100.fc32', 'release':'FC32', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-5.11.11-100.fc32', 'release':'FC32', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel / kernel-headers / kernel-tools');
}
