#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152320);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/11");

  script_cve_id(
    "CVE-2021-21261"
  );

  script_name(english:"EulerOS 2.0 SP8 : flatpak (EulerOS-SA-2021-2294)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the flatpak packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerability :

  - Flatpak is a system for building, distributing, and
    running sandboxed desktop applications on Linux. A bug
    was discovered in the `flatpak-portal` service that can
    allow sandboxed applications to execute arbitrary code
    on the host system (a sandbox escape). This
    sandbox-escape bug is present in versions from 0.11.4
    and before fixed versions 1.8.5 and 1.10.0. The Flatpak
    portal D-Bus service (`flatpak-portal`, also known by
    its D-Bus service name
    `org.freedesktop.portal.Flatpak`) allows apps in a
    Flatpak sandbox to launch their own subprocesses in a
    new sandbox instance, either with the same security
    settings as the caller or with more restrictive
    security settings. For example, this is used in
    Flatpak-packaged web browsers such as Chromium to
    launch subprocesses that will process untrusted web
    content, and give those subprocesses a more restrictive
    sandbox than the browser itself. In vulnerable
    versions, the Flatpak portal service passes
    caller-specified environment variables to non-sandboxed
    processes on the host system, and in particular to the
    `flatpak run` command that is used to launch the new
    sandbox instance. A malicious or compromised Flatpak
    app could set environment variables that are trusted by
    the `flatpak run` command, and use them to execute
    arbitrary code that is not in a sandbox. As a
    workaround, this vulnerability can be mitigated by
    preventing the `flatpak-portal` service from starting,
    but that mitigation will prevent many Flatpak apps from
    working correctly. This is fixed in versions 1.8.5 and
    1.10.0.(CVE-2021-21261)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2294
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?249ffb1e");
  script_set_attribute(attribute:"solution", value:
"Update the affected flatpak package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:flatpak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:flatpak-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["flatpak-1.0.3-1.h4.eulerosv2r8",
        "flatpak-libs-1.0.3-1.h4.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "flatpak");
}
