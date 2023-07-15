#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-616045ca76.
#

include("compat.inc");

if (description)
{
  script_id(124496);
  script_version("1.2");
  script_cvs_date("Date: 2019/09/23 11:21:10");

  script_xref(name:"FEDORA", value:"2019-616045ca76");

  script_name(english:"Fedora 30 : 1:grub2 / systemd (2019-616045ca76)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"In systemd: backport of bunch of patches from the v242 release. Most
important :

  - kernel-install will not create the boot loader entry
    automatically

  - a memory leak is fixed.

In grub2 :

  - 10_linux_bls: don't add --users option to generated menu
    entries (#1693515)

  - Only set blsdir if /boot/loader/entries is in a btrfs or
    zfs partition (#1688453)

  - Fix some BLS snippets not being displayed in the GRUB
    menu (#1691232)

  - Never remove boot loader configuration for other boot
    loaders from the ESP (#1648907)

  - Do not mask systemd's kernel-install scriptlets.

No need to log out or reboot.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-616045ca76"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 1:grub2 and / or systemd packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:1:grub2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:systemd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:30");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^30([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 30", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC30", reference:"grub2-2.02-75.fc30", epoch:"1")) flag++;
if (rpm_check(release:"FC30", reference:"systemd-241-4.gitcbf14c9.fc30")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "1:grub2 / systemd");
}
