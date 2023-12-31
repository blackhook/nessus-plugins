#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-10730.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(42786);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2009-1284");
  script_bugtraq_id(34332);
  script_xref(name:"FEDORA", value:"2009-10730");

  script_name(english:"Fedora 10 : texlive-2007-46.fc10 (2009-10730)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fri Oct 23 2009 Jindrich Novy <jnovy at redhat.com>
    2007-46

    - add missing dependency on kpathsea

    - Thu Oct 15 2009 Jindrich Novy <jnovy at redhat.com>
      2007-45

    - make kpathsea not dependent on texlive

    - fix lacheck again (#451513)

    - fix dvips configuration (#467542)

    - update kpathsea description and summary (#519257)

    - use upstream patch to fix pool overflow CVE-2009-1284
      (#492136)

    - don't complain if the pdvipsk hunks touching config.ps
      don't apply

    - avoid clashes with getline() from glibc

    - texlive-east-asian now requires
      texlive-texmf-east-asian (#487258)

    - do not attempt to remove old fonts via cron in
      /var/lib/texmf, fonts are stored in
      ~/.texlive2007/texmf-var per-user (#477833, #463975,
      #453468)

  - use correct paths in brp-* post install scriptlets
    (#468179)

    - fix build with gcc4.4

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=492136"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-November/031001.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f6f984a4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected texlive package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:texlive");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^10([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 10.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC10", reference:"texlive-2007-46.fc10")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "texlive");
}
