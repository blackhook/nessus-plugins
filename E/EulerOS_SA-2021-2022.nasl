#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151181);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/02");

  script_cve_id(
    "CVE-2021-23336"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.6.0 : python2 (EulerOS-SA-2021-2022)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the python2 packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerability :

  - The package python/cpython from 0 and before 3.6.13,
    from 3.7.0 and before 3.7.10, from 3.8.0 and before
    3.8.8, from 3.9.0 and before 3.9.2 are vulnerable to
    Web Cache Poisoning via urllib.parse.parse_qsl and
    urllib.parse.parse_qs by using a vector called
    parameter cloaking. When the attacker can separate
    query parameters using a semicolon (), they can cause a
    difference in the interpretation of the request between
    the proxy (running with default configuration) and the
    server. This can result in malicious requests being
    cached as completely safe ones, as the proxy would
    usually not see the semicolon as a separator, and
    therefore would not include it in a cache key of an
    unkeyed parameter.(CVE-2021-23336)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2022
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cd878902");
  script_set_attribute(attribute:"solution", value:
"Update the affected python2 package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-unversioned-command");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python2-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["python-unversioned-command-2.7.15-10.h30.eulerosv2r8",
        "python2-2.7.15-10.h30.eulerosv2r8",
        "python2-devel-2.7.15-10.h30.eulerosv2r8",
        "python2-libs-2.7.15-10.h30.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python2");
}
