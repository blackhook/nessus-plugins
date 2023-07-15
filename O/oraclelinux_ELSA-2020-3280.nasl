#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:3280 and 
# Oracle Linux Security Advisory ELSA-2020-3280 respectively.
#

include('compat.inc');

if (description)
{
  script_id(139397);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id(
    "CVE-2019-11756",
    "CVE-2019-17006",
    "CVE-2019-17023",
    "CVE-2020-12402"
  );
  script_xref(name:"RHSA", value:"2020:3280");

  script_name(english:"Oracle Linux 8 : nspr / nss (ELSA-2020-3280)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"From Red Hat Security Advisory 2020:3280 :

The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:3280 advisory.

  - nss: UAF in sftk_FreeSession due to improper refcounting
    (CVE-2019-11756)

  - nss: Check length of inputs for cryptographic primitives
    (CVE-2019-17006)

  - nss: TLS 1.3 HelloRetryRequest downgrade request sets
    client into invalid state (CVE-2019-17023)

  - nss: Side channel vulnerabilities during RSA key
    generation (CVE-2020-12402)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://oss.oracle.com/pipermail/el-errata/2020-August/010197.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected nspr and / or nss packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17006");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-softokn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-softokn-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-softokn-freebl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-softokn-freebl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nspr-4.25.0-2.el8_2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nspr-devel-4.25.0-2.el8_2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nss-3.53.1-11.el8_2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nss-devel-3.53.1-11.el8_2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nss-softokn-3.53.1-11.el8_2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nss-softokn-devel-3.53.1-11.el8_2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nss-softokn-freebl-3.53.1-11.el8_2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nss-softokn-freebl-devel-3.53.1-11.el8_2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nss-sysinit-3.53.1-11.el8_2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nss-tools-3.53.1-11.el8_2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nss-util-3.53.1-11.el8_2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nss-util-devel-3.53.1-11.el8_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nspr / nspr-devel / nss / nss-devel / nss-softokn / etc");
}
