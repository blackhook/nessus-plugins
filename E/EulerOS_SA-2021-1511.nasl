#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(147131);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/08");

  script_cve_id(
    "CVE-2020-25695"
  );

  script_name(english:"EulerOS Virtualization 3.0.6.6 : postgresql (EulerOS-SA-2021-1511)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the postgresql packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerability :

  - A flaw was found in PostgreSQL versions before 13.1,
    before 12.5, before 11.10, before 10.15, before 9.6.20
    and before 9.5.24. An attacker having permission to
    create non-temporary objects in at least one schema can
    execute arbitrary SQL functions under the identity of a
    superuser. The highest threat from this vulnerability
    is to data confidentiality and integrity as well as
    system availability.(CVE-2020-25695)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1511
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?37e6b97f");
  script_set_attribute(attribute:"solution", value:
"Update the affected postgresql package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.6");
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
if (uvp != "3.0.6.6") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.6");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["postgresql-9.2.24-1.h1.eulerosv2r7",
        "postgresql-contrib-9.2.24-1.h1.eulerosv2r7",
        "postgresql-devel-9.2.24-1.h1.eulerosv2r7",
        "postgresql-docs-9.2.24-1.h1.eulerosv2r7",
        "postgresql-libs-9.2.24-1.h1.eulerosv2r7",
        "postgresql-plperl-9.2.24-1.h1.eulerosv2r7",
        "postgresql-plpython-9.2.24-1.h1.eulerosv2r7",
        "postgresql-pltcl-9.2.24-1.h1.eulerosv2r7",
        "postgresql-server-9.2.24-1.h1.eulerosv2r7",
        "postgresql-test-9.2.24-1.h1.eulerosv2r7"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql");
}
