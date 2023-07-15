#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-fe299b3fa3.
#

include("compat.inc");

if (description)
{
  script_id(141249);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/09");

  script_cve_id("CVE-2020-5238");
  script_xref(name:"FEDORA", value:"2020-fe299b3fa3");

  script_name(english:"Fedora 31 : ghc-cmark-gfm / ghc-hakyll / gitit / pandoc / pandoc-citeproc / etc (2020-fe299b3fa3)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Security fix for CVE-2020-5238

  - ghc-cmark-gfm updated to 0.2.2 which rebases the bundled
    cmark-gfm to 0.29.0.gfm.1

https://github.com/github/cmark-gfm/security/advisories/GHSA-7gc6-9qr5
-hc85

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-fe299b3fa3"
  );
  # https://github.com/github/cmark-gfm/security/advisories/GHSA-7gc6-9qr5-hc85
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?374af7be"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ghc-cmark-gfm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ghc-hakyll");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gitit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pandoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pandoc-citeproc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:patat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:31");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^31([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 31", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC31", reference:"ghc-cmark-gfm-0.2.2-1.fc31")) flag++;
if (rpm_check(release:"FC31", reference:"ghc-hakyll-4.12.5.2-2.fc31")) flag++;
if (rpm_check(release:"FC31", reference:"gitit-0.12.3.2-4.fc31")) flag++;
if (rpm_check(release:"FC31", reference:"pandoc-2.5-2.fc31")) flag++;
if (rpm_check(release:"FC31", reference:"pandoc-citeproc-0.15.0.1-2.fc31")) flag++;
if (rpm_check(release:"FC31", reference:"patat-0.8.2.3-2.fc31")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghc-cmark-gfm / ghc-hakyll / gitit / pandoc / pandoc-citeproc / etc");
}
