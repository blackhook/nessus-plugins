#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-e16ba9e54e.
#

include("compat.inc");

if (description)
{
  script_id(132661);
  script_version("1.1");
  script_cvs_date("Date: 2020/01/06");

  script_xref(name:"FEDORA", value:"2019-e16ba9e54e");

  script_name(english:"Fedora 31 : wordpress (2019-e16ba9e54e)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**WordPress 5.3.2 Maintenance Release**

Shortly after WordPress 5.3.1 was released, a couple of high severity
Trac tickets were opened. The Core team scheduled this quick
maintenance release to resolve these issues.

Main issues addressed in 5.3.2 :

  - Date/Time: Ensure that get_feed_build_date() correctly
    handles a modified post object with invalid date.

  - Uploads: Fix file name collision in wp_unique_filename()
    when uploading a file with upper case extension on non
    case-sensitive file systems.

  - Media: Fix PHP warnings in wp_unique_filename() when the
    destination directory is unreadable.

  - Administration: Fix the colors in all color schemes for
    buttons with the .active class.

  - Posts, Post Types: In wp_insert_post(), when checking
    the post date to set future or publish status, use a
    proper delta comparison.

----

See: [WordPress 5.3.1 Security and Maintenance
Release](https://wordpress.org/news/2019/12/wordpress-5-3-1-security-a
nd-maintenance-release/)

**Four security issues** affect WordPress versions 5.3 and earlier;
version 5.3.1 fixes them, so you&rsquo;ll want to upgrade. If you
haven&rsquo;t yet updated to 5.3, there are also updated versions of
5.2 and earlier that fix the security issues.

  - Props to Daniel Bachhuber for finding an issue where an
    unprivileged user could make a post sticky via the REST
    API.

  - Props to Simon Scannell of RIPS Technologies for finding
    and disclosing an issue where cross-site scripting (XSS)
    could be stored in well-crafted links.

  - Props to the WordPress.org Security Team for hardening
    wp_kses_bad_protocol() to ensure that it is aware of the
    named colon attribute.

  - Props to Nguyen The Duc for discovering a stored XSS
    vulnerability using block editor content.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-e16ba9e54e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wordpress package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:31");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/06");
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
if (rpm_check(release:"FC31", reference:"wordpress-5.3.2-1.fc31")) flag++;


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
