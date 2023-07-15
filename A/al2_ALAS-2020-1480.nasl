#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2020-1480.
#

include('compat.inc');

if (description)
{
  script_id(139858);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id(
    "CVE-2017-18232",
    "CVE-2018-8043",
    "CVE-2018-10323",
    "CVE-2019-3016",
    "CVE-2019-9445",
    "CVE-2019-18808",
    "CVE-2019-19054",
    "CVE-2019-19061",
    "CVE-2019-19073",
    "CVE-2019-19074",
    "CVE-2020-10781",
    "CVE-2020-12655",
    "CVE-2020-15393"
  );
  script_bugtraq_id(103354, 103423);
  script_xref(name:"ALAS", value:"2020-1480");

  script_name(english:"Amazon Linux 2 : kernel (ALAS-2020-1480)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the ALAS2-2020-1480 advisory.

  - The Serial Attached SCSI (SAS) implementation in the Linux kernel through 4.15.9 mishandles a mutex within
    libsas, which allows local users to cause a denial of service (deadlock) by triggering certain error-
    handling code. (CVE-2017-18232)

  - The unimac_mdio_probe function in drivers/net/phy/mdio-bcm-unimac.c in the Linux kernel through 4.15.8
    does not validate certain resource availability, which allows local users to cause a denial of service
    (NULL pointer dereference). (CVE-2018-8043)

  - A memory leak in the ccp_run_sha_cmd() function in drivers/crypto/ccp/ccp-ops.c in the Linux kernel
    through 5.3.9 allows attackers to cause a denial of service (memory consumption), aka CID-128c66429247.
    (CVE-2019-18808)

  - A memory leak in the cx23888_ir_probe() function in drivers/media/pci/cx23885/cx23888-ir.c in the Linux
    kernel through 5.3.11 allows attackers to cause a denial of service (memory consumption) by triggering
    kfifo_alloc() failures, aka CID-a7b2df76b42b. (CVE-2019-19054)

  - A memory leak in the adis_update_scan_mode_burst() function in drivers/iio/imu/adis_buffer.c in the Linux
    kernel before 5.3.9 allows attackers to cause a denial of service (memory consumption), aka
    CID-9c0530e898f3. (CVE-2019-19061)

  - Memory leaks in drivers/net/wireless/ath/ath9k/htc_hst.c in the Linux kernel through 5.3.11 allow
    attackers to cause a denial of service (memory consumption) by triggering wait_for_completion_timeout()
    failures. This affects the htc_config_pipe_credits() function, the htc_setup_complete() function, and the
    htc_connect_service() function, aka CID-853acf7caf10. (CVE-2019-19073)

  - A memory leak in the ath9k_wmi_cmd() function in drivers/net/wireless/ath/ath9k/wmi.c in the Linux kernel
    through 5.3.11 allows attackers to cause a denial of service (memory consumption), aka CID-728c1e2a05e4.
    (CVE-2019-19074)

  - In a Linux KVM guest that has PV TLB enabled, a process in the guest kernel may be able to read memory
    locations from another process in the same guest. This problem is limit to the host running linux kernel
    4.10 with a guest running linux kernel 4.16 or later. The problem mainly affects AMD processors but Intel
    CPUs cannot be ruled out. (CVE-2019-3016)

  - In the Android kernel in F2FS driver there is a possible out of bounds read due to a missing bounds check.
    This could lead to local information disclosure with system execution privileges needed. User interaction
    is not needed for exploitation. (CVE-2019-9445)

  - An issue was discovered in xfs_agf_verify in fs/xfs/libxfs/xfs_alloc.c in the Linux kernel through 5.6.10.
    Attackers may trigger a sync of excessive duration via an XFS v5 image with crafted metadata, aka
    CID-d0c7feaf8767. (CVE-2020-12655)

  - In the Linux kernel through 5.7.6, usbtest_disconnect in drivers/usb/misc/usbtest.c has a memory leak, aka
    CID-28ebeb8db770. (CVE-2020-15393)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2020-1480.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2017-18232");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-10323");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-8043");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-18808");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19054");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19061");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19073");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19074");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-3016");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-9445");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10781");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-12655");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-15393");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update kernel' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9445");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-3016");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-livepatch-4.14.192-147.314");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");
include("hotfixes.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (get_one_kb_item("Host/kpatch/kernel-cves"))
{
  set_hotfix_type("kpatch");
  cve_list = make_list("CVE-2017-18232", "CVE-2018-8043", "CVE-2018-10323", "CVE-2019-3016", "CVE-2019-9445", "CVE-2019-18808", "CVE-2019-19054", "CVE-2019-19061", "CVE-2019-19073", "CVE-2019-19074", "CVE-2020-10781", "CVE-2020-12655", "CVE-2020-15393");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALAS-2020-1480");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}
pkgs = [
    {'reference':'kernel-4.14.192-147.314.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-4.14.192-147.314.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-debuginfo-4.14.192-147.314.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-debuginfo-4.14.192-147.314.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-debuginfo-common-aarch64-4.14.192-147.314.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-debuginfo-common-x86_64-4.14.192-147.314.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-devel-4.14.192-147.314.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-devel-4.14.192-147.314.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-headers-4.14.192-147.314.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-headers-4.14.192-147.314.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'kernel-headers-4.14.192-147.314.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-livepatch-4.14.192-147.314-1.0-0.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-tools-4.14.192-147.314.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-tools-4.14.192-147.314.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-tools-debuginfo-4.14.192-147.314.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-tools-debuginfo-4.14.192-147.314.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-tools-devel-4.14.192-147.314.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-tools-devel-4.14.192-147.314.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'perf-4.14.192-147.314.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'perf-4.14.192-147.314.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'perf-debuginfo-4.14.192-147.314.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'perf-debuginfo-4.14.192-147.314.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'python-perf-4.14.192-147.314.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'python-perf-4.14.192-147.314.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'python-perf-debuginfo-4.14.192-147.314.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'python-perf-debuginfo-4.14.192-147.314.amzn2', 'cpu':'x86_64', 'release':'AL2'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debuginfo / kernel-debuginfo-common-x86_64 / etc");
}
