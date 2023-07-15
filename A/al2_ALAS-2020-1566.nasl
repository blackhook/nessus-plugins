##
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2020-1566.
##

include('compat.inc');

if (description)
{
  script_id(143589);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id(
    "CVE-2019-19770",
    "CVE-2020-8694",
    "CVE-2020-14351",
    "CVE-2020-25656",
    "CVE-2020-25668",
    "CVE-2020-25669",
    "CVE-2020-25704",
    "CVE-2020-27673",
    "CVE-2020-27675",
    "CVE-2020-27777",
    "CVE-2020-28941",
    "CVE-2020-28974"
  );
  script_xref(name:"ALAS", value:"2020-1566");

  script_name(english:"Amazon Linux 2 : kernel (ALAS-2020-1566)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the ALAS2-2020-1566 advisory.

  - ** DISPUTED ** In the Linux kernel 4.19.83, there is a use-after-free (read) in the debugfs_remove
    function in fs/debugfs/inode.c (which is used to remove a file or directory in debugfs that was previously
    created with a call to another debugfs function such as debugfs_create_file). NOTE: Linux kernel
    developers dispute this issue as not being an issue with debugfs, instead this is an issue with misuse of
    debugfs within blktrace. (CVE-2019-19770)

  - A flaw was found in the Linux kernel. A use-after-free memory flaw was found in the perf subsystem
    allowing a local attacker with permission to monitor perf events to corrupt memory and possibly escalate
    privileges. The highest threat from this vulnerability is to data confidentiality and integrity as well as
    system availability. (CVE-2020-14351)

  - A flaw was found in the Linux kernel. A use-after-free was found in the way the console subsystem was
    using ioctls KDGKBSENT and KDSKBSENT. A local user could use this flaw to get read memory access out of
    bounds. The highest threat from this vulnerability is to data confidentiality. (CVE-2020-25656)

  - A flaw memory leak in the Linux kernel performance monitoring subsystem was found in the way if using
    PERF_EVENT_IOC_SET_FILTER. A local user could use this flaw to starve the resources causing denial of
    service. (CVE-2020-25704)

  - An issue was discovered in the Linux kernel through 5.9.1, as used with Xen through 4.14.x. Guest OS users
    can cause a denial of service (host OS hang) via a high rate of events to dom0, aka CID-e99502f76271.
    (CVE-2020-27673)

  - An issue was discovered in the Linux kernel through 5.9.1, as used with Xen through 4.14.x.
    drivers/xen/events/events_base.c allows event-channel removal during the event-handling loop (a race
    condition). This can cause a use-after-free or NULL pointer dereference, as demonstrated by a dom0 crash
    via events for an in-reconfiguration paravirtualized device, aka CID-073d0552ead5. (CVE-2020-27675)

  - An issue was discovered in drivers/accessibility/speakup/spk_ttyio.c in the Linux kernel through 5.9.9.
    Local attackers on systems with the speakup driver could cause a local denial of service attack, aka
    CID-d41227544427. This occurs because of an invalid free when the line discipline is used more than once.
    (CVE-2020-28941)

  - A slab-out-of-bounds read in fbcon in the Linux kernel before 5.9.7 could be used by local attackers to
    read privileged information or potentially crash the kernel, aka CID-3c4e0dff2095. This occurs because
    KD_FONT_OP_COPY in drivers/tty/vt/vt.c can be used for manipulations such as font height. (CVE-2020-28974)

  - Insufficient access control in the Linux kernel driver for some Intel(R) Processors may allow an
    authenticated user to potentially enable information disclosure via local access. (CVE-2020-8694)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2020-1566.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19770");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14351");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25656");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25668");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25669");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25704");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-27673");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-27675");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-27777");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-28941");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-28974");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-8694");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update kernel' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27777");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-19770");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-livepatch-4.14.209-160.335");
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
  cve_list = make_list("CVE-2019-19770", "CVE-2020-8694", "CVE-2020-14351", "CVE-2020-25656", "CVE-2020-25668", "CVE-2020-25669", "CVE-2020-25704", "CVE-2020-27673", "CVE-2020-27675", "CVE-2020-27777", "CVE-2020-28941", "CVE-2020-28974");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALAS-2020-1566");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}
pkgs = [
    {'reference':'kernel-4.14.209-160.335.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-4.14.209-160.335.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-debuginfo-4.14.209-160.335.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-debuginfo-4.14.209-160.335.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-debuginfo-common-aarch64-4.14.209-160.335.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-debuginfo-common-x86_64-4.14.209-160.335.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-devel-4.14.209-160.335.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-devel-4.14.209-160.335.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-headers-4.14.209-160.335.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-headers-4.14.209-160.335.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'kernel-headers-4.14.209-160.335.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-livepatch-4.14.209-160.335-1.0-0.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-tools-4.14.209-160.335.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-tools-4.14.209-160.335.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-tools-debuginfo-4.14.209-160.335.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-tools-debuginfo-4.14.209-160.335.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-tools-devel-4.14.209-160.335.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-tools-devel-4.14.209-160.335.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'perf-4.14.209-160.335.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'perf-4.14.209-160.335.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'perf-debuginfo-4.14.209-160.335.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'perf-debuginfo-4.14.209-160.335.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'python-perf-4.14.209-160.335.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'python-perf-4.14.209-160.335.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'python-perf-debuginfo-4.14.209-160.335.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'python-perf-debuginfo-4.14.209-160.335.amzn2', 'cpu':'x86_64', 'release':'AL2'}
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
      severity   : SECURITY_HOLE,
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