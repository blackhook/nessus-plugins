#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:2250 and 
# Oracle Linux Security Advisory ELSA-2020-2250 respectively.
#

include("compat.inc");

if (description)
{
  script_id(137345);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/18");

  script_cve_id("CVE-2020-1108", "CVE-2020-1161");
  script_xref(name:"RHSA", value:"2020:2250");

  script_name(english:"Oracle Linux 8 : dotnet3.1 (ELSA-2020-2250)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"From Red Hat Security Advisory 2020:2250 :

The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:2250 advisory.

  - dotnet: Denial of service via untrusted input
    (CVE-2020-1108)

  - dotnet: Denial of service due to infinite loop
    (CVE-2020-1161)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2020-June/010028.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected dotnet3.1 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:aspnetcore-runtime-3.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:aspnetcore-targeting-pack-3.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dotnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dotnet-apphost-pack-3.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dotnet-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dotnet-hostfxr-3.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dotnet-runtime-3.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dotnet-sdk-3.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dotnet-targeting-pack-3.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dotnet-templates-3.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:netstandard-targeting-pack-2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 8", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"aspnetcore-runtime-3.1-3.1.4-2.0.2.el8_2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"aspnetcore-targeting-pack-3.1-3.1.4-2.0.2.el8_2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"dotnet-3.1.104-2.0.2.el8_2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"dotnet-apphost-pack-3.1-3.1.4-2.0.2.el8_2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"dotnet-host-3.1.4-2.0.2.el8_2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"dotnet-hostfxr-3.1-3.1.4-2.0.2.el8_2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"dotnet-runtime-3.1-3.1.4-2.0.2.el8_2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"dotnet-sdk-3.1-3.1.104-2.0.2.el8_2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"dotnet-targeting-pack-3.1-3.1.4-2.0.2.el8_2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"dotnet-templates-3.1-3.1.104-2.0.2.el8_2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"netstandard-targeting-pack-2.1-3.1.104-2.0.2.el8_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "aspnetcore-runtime-3.1 / aspnetcore-targeting-pack-3.1 / dotnet / etc");
}
