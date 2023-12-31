#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-aaefb84ff3.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105949);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_xref(name:"FEDORA", value:"2017-aaefb84ff3");

  script_name(english:"Fedora 27 : wordpress (2017-aaefb84ff3)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Upstream announcement :

**WordPress 4.8.2 is now available**. This is a security release for
all previous versions and we strongly encourage you to update your
sites immediately.

WordPress versions 4.8.1 and earlier are affected by these security
issues :

  - $wpdb->prepare() can create unexpected and unsafe
    queries leading to potential SQL injection (SQLi).
    WordPress core is not directly vulnerable to this issue,
    but we&rsquo;ve added hardening to prevent plugins and
    themes from accidentally causing a vulnerability.
    Reported by Slavco

  - A cross-site scripting (XSS) vulnerability was
    discovered in the oEmbed discovery. Reported by xknown
    of the WordPress Security Team.

  - A cross-site scripting (XSS) vulnerability was
    discovered in the visual editor. Reported by Rodolfo
    Assis (@brutelogic) of Sucuri Security.

  - A path traversal vulnerability was discovered in the
    file unzipping code. Reported by Alex Chapman (noxrnet).

  - A cross-site scripting (XSS) vulnerability was
    discovered in the plugin editor. Reported by
    &#x9648;&#x745E;&#x7426; (Chen Ruiqi).

  - An open redirect was discovered on the user and term
    edit screens. Reported by Yasin Soliman (ysx).

  - A path traversal vulnerability was discovered in the
    customizer. Reported by Weston Ruter of the WordPress
    Security Team.

  - A cross-site scripting (XSS) vulnerability was
    discovered in template names. Reported by Luka (sikic).

  - A cross-site scripting (XSS) vulnerability was
    discovered in the link modal. Reported by Anas Roubi
    (qasuar).

Thank you to the reporters of these issues for practicing [responsible
disclosure](https://make.wordpress.org/core/handbook/testing/reporting
-security-vulnerabilities/).

In addition to the security issues above, WordPress 4.8.2 contains 6
maintenance fixes to the 4.8 release series. For more information, see
the [release notes](https://codex.wordpress.org/Version_4.8.2) or
consult the [list of
changes](https://core.trac.wordpress.org/query?status=closed&milestone
=4.8.2&group=component&col=id&col=summary&col=component&col=status&col
=owner&col=type&col=priority&col=keywords&order=priority).

Thanks to everyone who contributed to 4.8.2.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-aaefb84ff3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://codex.wordpress.org/Version_4.8.2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wordpress package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:27");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^27([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 27", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC27", reference:"wordpress-4.8.2-1.fc27")) flag++;


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
