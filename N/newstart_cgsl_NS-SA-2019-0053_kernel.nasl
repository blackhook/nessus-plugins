#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0053. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127240);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2018-18559");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : kernel Vulnerability (NS-SA-2019-0053)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has kernel packages installed that are affected by
a vulnerability:

  - A use-after-free flaw can occur in the Linux kernel due
    to a race condition between packet_do_bind() and
    packet_notifier() functions called for an AF_PACKET
    socket. An unprivileged, local user could use this flaw
    to induce kernel memory corruption on the system,
    leading to an unresponsive system or to a crash. Due to
    the nature of the flaw, privilege escalation cannot be
    fully ruled out. (CVE-2018-18559)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0053");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-18559");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "kernel-3.10.0-693.21.1.el7.cgslv5_4.10.268.g514b111.lite",
    "kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5_4.10.268.g514b111.lite",
    "kernel-core-3.10.0-693.21.1.el7.cgslv5_4.10.268.g514b111.lite",
    "kernel-debug-core-3.10.0-693.21.1.el7.cgslv5_4.10.268.g514b111.lite",
    "kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.10.268.g514b111.lite",
    "kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5_4.10.268.g514b111.lite",
    "kernel-debug-modules-3.10.0-693.21.1.el7.cgslv5_4.10.268.g514b111.lite",
    "kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.10.268.g514b111.lite",
    "kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5_4.10.268.g514b111.lite",
    "kernel-devel-3.10.0-693.21.1.el7.cgslv5_4.10.268.g514b111.lite",
    "kernel-doc-3.10.0-693.21.1.el7.cgslv5_4.10.268.g514b111.lite",
    "kernel-headers-3.10.0-693.21.1.el7.cgslv5_4.10.268.g514b111.lite",
    "kernel-modules-3.10.0-693.21.1.el7.cgslv5_4.10.268.g514b111.lite",
    "kernel-tools-3.10.0-693.21.1.el7.cgslv5_4.10.268.g514b111.lite",
    "kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.10.268.g514b111.lite",
    "kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5_4.10.268.g514b111.lite",
    "kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5_4.10.268.g514b111.lite",
    "perf-3.10.0-693.21.1.el7.cgslv5_4.10.268.g514b111.lite",
    "perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.10.268.g514b111.lite",
    "python-perf-3.10.0-693.21.1.el7.cgslv5_4.10.268.g514b111.lite",
    "python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.10.268.g514b111.lite"
  ],
  "CGSL MAIN 5.04": [
    "kernel-3.10.0-693.21.1.el7.cgslv5_4.10.265.gcc0fd42",
    "kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5_4.10.265.gcc0fd42",
    "kernel-debug-3.10.0-693.21.1.el7.cgslv5_4.10.265.gcc0fd42",
    "kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.10.265.gcc0fd42",
    "kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5_4.10.265.gcc0fd42",
    "kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.10.265.gcc0fd42",
    "kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5_4.10.265.gcc0fd42",
    "kernel-devel-3.10.0-693.21.1.el7.cgslv5_4.10.265.gcc0fd42",
    "kernel-doc-3.10.0-693.21.1.el7.cgslv5_4.10.265.gcc0fd42",
    "kernel-headers-3.10.0-693.21.1.el7.cgslv5_4.10.265.gcc0fd42",
    "kernel-tools-3.10.0-693.21.1.el7.cgslv5_4.10.265.gcc0fd42",
    "kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.10.265.gcc0fd42",
    "kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5_4.10.265.gcc0fd42",
    "kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5_4.10.265.gcc0fd42",
    "perf-3.10.0-693.21.1.el7.cgslv5_4.10.265.gcc0fd42",
    "perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.10.265.gcc0fd42",
    "python-perf-3.10.0-693.21.1.el7.cgslv5_4.10.265.gcc0fd42",
    "python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.10.265.gcc0fd42"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
