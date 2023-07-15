#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0115. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154563);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/27");

  script_cve_id(
    "CVE-2019-19055",
    "CVE-2019-19807",
    "CVE-2020-24394",
    "CVE-2021-27363",
    "CVE-2021-27365"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : kernel Multiple Vulnerabilities (NS-SA-2021-0115)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has kernel packages installed that are affected by
multiple vulnerabilities:

  - ** DISPUTED ** A memory leak in the nl80211_get_ftm_responder_stats() function in net/wireless/nl80211.c
    in the Linux kernel through 5.3.11 allows attackers to cause a denial of service (memory consumption) by
    triggering nl80211hdr_put() failures, aka CID-1399c59fa929. NOTE: third parties dispute the relevance of
    this because it occurs on a code path where a successful allocation has already occurred. (CVE-2019-19055)

  - In the Linux kernel before 5.3.11, sound/core/timer.c has a use-after-free caused by erroneous code
    refactoring, aka CID-e7af6307a8a5. This is related to snd_timer_open and snd_timer_close_locked. The
    timeri variable was originally intended to be for a newly created timer instance, but was used for a
    different purpose after refactoring. (CVE-2019-19807)

  - In the Linux kernel before 5.7.8, fs/nfsd/vfs.c (in the NFS server) can set incorrect permissions on new
    filesystem objects when the filesystem lacks ACL support, aka CID-22cf8419f131. This occurs because the
    current umask is not considered. (CVE-2020-24394)

  - An issue was discovered in the Linux kernel through 5.11.3. A kernel pointer leak can be used to determine
    the address of the iscsi_transport structure. When an iSCSI transport is registered with the iSCSI
    subsystem, the transport's handle is available to unprivileged users via the sysfs file system, at
    /sys/class/iscsi_transport/$TRANSPORT_NAME/handle. When read, the show_transport_handle function (in
    drivers/scsi/scsi_transport_iscsi.c) is called, which leaks the handle. This handle is actually the
    pointer to an iscsi_transport struct in the kernel module's global variables. (CVE-2021-27363)

  - An issue was discovered in the Linux kernel through 5.11.3. Certain iSCSI data structures do not have
    appropriate length constraints or checks, and can exceed the PAGE_SIZE value. An unprivileged user can
    send a Netlink message that is associated with iSCSI, and has a length up to the maximum length of a
    Netlink message. (CVE-2021-27365)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0115");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-19055");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-19807");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-24394");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-27363");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-27365");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19807");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-sign-keys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-sign-keys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.04': [
    'kernel-3.10.0-693.21.1.el7.cgslv5_4.57.975.gda06df7.lite',
    'kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5_4.57.975.gda06df7.lite',
    'kernel-core-3.10.0-693.21.1.el7.cgslv5_4.57.975.gda06df7.lite',
    'kernel-debug-core-3.10.0-693.21.1.el7.cgslv5_4.57.975.gda06df7.lite',
    'kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.57.975.gda06df7.lite',
    'kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5_4.57.975.gda06df7.lite',
    'kernel-debug-modules-3.10.0-693.21.1.el7.cgslv5_4.57.975.gda06df7.lite',
    'kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.57.975.gda06df7.lite',
    'kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5_4.57.975.gda06df7.lite',
    'kernel-devel-3.10.0-693.21.1.el7.cgslv5_4.57.975.gda06df7.lite',
    'kernel-headers-3.10.0-693.21.1.el7.cgslv5_4.57.975.gda06df7.lite',
    'kernel-modules-3.10.0-693.21.1.el7.cgslv5_4.57.975.gda06df7.lite',
    'kernel-sign-keys-3.10.0-693.21.1.el7.cgslv5_4.57.975.gda06df7.lite',
    'kernel-tools-3.10.0-693.21.1.el7.cgslv5_4.57.975.gda06df7.lite',
    'kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.57.975.gda06df7.lite',
    'kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5_4.57.975.gda06df7.lite',
    'kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5_4.57.975.gda06df7.lite',
    'perf-3.10.0-693.21.1.el7.cgslv5_4.57.975.gda06df7.lite',
    'perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.57.975.gda06df7.lite',
    'python-perf-3.10.0-693.21.1.el7.cgslv5_4.57.975.gda06df7.lite',
    'python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.57.975.gda06df7.lite'
  ],
  'CGSL MAIN 5.04': [
    'kernel-3.10.0-693.21.1.el7.cgslv5_4.55.1047.g8ce207e',
    'kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5_4.55.1047.g8ce207e',
    'kernel-debug-3.10.0-693.21.1.el7.cgslv5_4.55.1047.g8ce207e',
    'kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.55.1047.g8ce207e',
    'kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5_4.55.1047.g8ce207e',
    'kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.55.1047.g8ce207e',
    'kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5_4.55.1047.g8ce207e',
    'kernel-devel-3.10.0-693.21.1.el7.cgslv5_4.55.1047.g8ce207e',
    'kernel-headers-3.10.0-693.21.1.el7.cgslv5_4.55.1047.g8ce207e',
    'kernel-sign-keys-3.10.0-693.21.1.el7.cgslv5_4.55.1047.g8ce207e',
    'kernel-tools-3.10.0-693.21.1.el7.cgslv5_4.55.1047.g8ce207e',
    'kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.55.1047.g8ce207e',
    'kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5_4.55.1047.g8ce207e',
    'kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5_4.55.1047.g8ce207e',
    'perf-3.10.0-693.21.1.el7.cgslv5_4.55.1047.g8ce207e',
    'perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.55.1047.g8ce207e',
    'python-perf-3.10.0-693.21.1.el7.cgslv5_4.55.1047.g8ce207e',
    'python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.55.1047.g8ce207e'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel');
}
