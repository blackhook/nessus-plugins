#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-a1f140614b.
#

include("compat.inc");

if (description)
{
  script_id(140307);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/16");

  script_cve_id("CVE-2020-6532", "CVE-2020-6537", "CVE-2020-6538", "CVE-2020-6539", "CVE-2020-6540", "CVE-2020-6541", "CVE-2020-6542", "CVE-2020-6543", "CVE-2020-6544", "CVE-2020-6545", "CVE-2020-6546", "CVE-2020-6547", "CVE-2020-6548", "CVE-2020-6549", "CVE-2020-6550", "CVE-2020-6551", "CVE-2020-6552", "CVE-2020-6553", "CVE-2020-6554", "CVE-2020-6555", "CVE-2020-6556", "CVE-2020-6559", "CVE-2020-6560", "CVE-2020-6561", "CVE-2020-6562", "CVE-2020-6563", "CVE-2020-6564", "CVE-2020-6565", "CVE-2020-6566", "CVE-2020-6567", "CVE-2020-6568", "CVE-2020-6569", "CVE-2020-6570", "CVE-2020-6571");
  script_xref(name:"FEDORA", value:"2020-a1f140614b");

  script_name(english:"Fedora 32 : chromium (2020-a1f140614b)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Update to Chromium 85.0.4183.83. Bugs fixed, security holes patched,
and features added. Hold on to your butts.

List of CVEs resolved with this update: CVE-2020-6532 CVE-2020-6537
CVE-2020-6538 CVE-2020-6539 CVE-2020-6540 CVE-2020-6541 CVE-2020-6542
CVE-2020-6543 CVE-2020-6544 CVE-2020-6545 CVE-2020-6546 CVE-2020-6547
CVE-2020-6548 CVE-2020-6549 CVE-2020-6550 CVE-2020-6551 CVE-2020-6552
CVE-2020-6553 CVE-2020-6554 CVE-2020-6555 CVE-2020-6556 CVE-2020-6559
CVE-2020-6560 CVE-2020-6561 CVE-2020-6562 CVE-2020-6563 CVE-2020-6564
CVE-2020-6565 CVE-2020-6566 CVE-2020-6567 CVE-2020-6568 CVE-2020-6569
CVE-2020-6570 CVE-2020-6571

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-a1f140614b"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected chromium package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:32");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/08");
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
if (! preg(pattern:"^32([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 32", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC32", reference:"chromium-85.0.4183.83-1.fc32", allowmaj:TRUE)) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromium");
}
