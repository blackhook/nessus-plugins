#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0212. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131776);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2018-9568", "CVE-2019-11810", "CVE-2019-14835");
  script_bugtraq_id(108286);

  script_name(english:"NewStart CGSL MAIN 4.06 : kernel Multiple Vulnerabilities (NS-SA-2019-0212)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.06, has kernel packages installed that are affected by multiple
vulnerabilities:

  - In sk_clone_lock of sock.c, there is a possible memory
    corruption due to type confusion. This could lead to
    local escalation of privilege with no additional
    execution privileges needed. User interaction is not
    needed for exploitation. Product: Android. Versions:
    Android kernel. Android ID: A-113509306. References:
    Upstream kernel. (CVE-2018-9568)

  - An issue was discovered in the Linux kernel before
    5.0.7. A NULL pointer dereference can occur when
    megasas_create_frame_pool() fails in
    megasas_alloc_cmds() in
    drivers/scsi/megaraid/megaraid_sas_base.c. This causes a
    Denial of Service, related to a use-after-free.
    (CVE-2019-11810)

  - A buffer overflow flaw was found, in versions from
    2.6.34 to 5.2.x, in the way Linux kernel's vhost
    functionality that translates virtqueue buffers to IOVs,
    logged the buffer descriptors during migration. A
    privileged guest user able to pass descriptors with
    invalid length to the host when migration is underway,
    could use this flaw to increase their privileges on the
    host. (CVE-2019-14835)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0212");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14835");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/06");

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

if (release !~ "CGSL MAIN 4.06")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.06');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 4.06": [
    "kernel-2.6.32-754.23.1.el6.cgslv4_6.0.28.g7cb8882",
    "kernel-abi-whitelists-2.6.32-754.23.1.el6.cgslv4_6.0.28.g7cb8882",
    "kernel-debug-2.6.32-754.23.1.el6.cgslv4_6.0.28.g7cb8882",
    "kernel-debug-debuginfo-2.6.32-754.23.1.el6.cgslv4_6.0.28.g7cb8882",
    "kernel-debug-devel-2.6.32-754.23.1.el6.cgslv4_6.0.28.g7cb8882",
    "kernel-debuginfo-2.6.32-754.23.1.el6.cgslv4_6.0.28.g7cb8882",
    "kernel-debuginfo-common-x86_64-2.6.32-754.23.1.el6.cgslv4_6.0.28.g7cb8882",
    "kernel-devel-2.6.32-754.23.1.el6.cgslv4_6.0.28.g7cb8882",
    "kernel-doc-2.6.32-754.23.1.el6.cgslv4_6.0.28.g7cb8882",
    "kernel-firmware-2.6.32-754.23.1.el6.cgslv4_6.0.28.g7cb8882",
    "kernel-headers-2.6.32-754.23.1.el6.cgslv4_6.0.28.g7cb8882",
    "perf-2.6.32-754.23.1.el6.cgslv4_6.0.28.g7cb8882",
    "perf-debuginfo-2.6.32-754.23.1.el6.cgslv4_6.0.28.g7cb8882",
    "python-perf-2.6.32-754.23.1.el6.cgslv4_6.0.28.g7cb8882",
    "python-perf-debuginfo-2.6.32-754.23.1.el6.cgslv4_6.0.28.g7cb8882"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
