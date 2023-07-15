#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-fa71ca92f8.
#

include("compat.inc");

if (description)
{
  script_id(136441);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/11");
  script_xref(name:"FEDORA", value:"2020-fa71ca92f8");

  script_name(english:"Fedora 30 : wordpress (2020-fa71ca92f8)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**WordPress 5.4.1**

Security Updates

Seven security issues affect WordPress versions 5.4 and earlier. If
you haven&rsquo;t yet updated to 5.4, all WordPress versions since 3.7
have also been updated to fix the following security issues :

  - Props to Muaz Bin Abdus Sattar and Jannes who both
    independently reported an issue where password reset
    tokens were not properly invalidated

  - Props to ka1n4t for finding an issue where certain
    private posts can be viewed unauthenticated

  - Props to Evan Ricafort for discovering an XSS issue in
    the Customizer

  - Props to Ben Bidner from the WordPress Security Team who
    discovered an XSS issue in the search block

  - Props to Nick Daugherty from WordPress VIP / WordPress
    Security Team who discovered an XSS issue in
    wp-object-cache

  - Props to Ronnie Goodrich (Kahoots) and Jason Medeiros
    who independently reported an XSS issue in file uploads.

  - Props to Weston Ruter for fixing a stored XSS
    vulnerability in the WordPress customizer.

  - Additionally, an authenticated XSS issue in the block
    editor was discovered by Nguyen the Duc in WordPress 5.4
    RC1 and RC2. It was fixed in 5.4 RC5. We wanted to be
    sure to give credit and thank them for all of their work
    in making WordPress more secure.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-fa71ca92f8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wordpress package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:30");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/11");
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
if (! preg(pattern:"^30([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 30", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC30", reference:"wordpress-5.4.1-1.fc30")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wordpress");
}
