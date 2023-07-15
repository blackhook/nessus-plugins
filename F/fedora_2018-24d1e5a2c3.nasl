#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-24d1e5a2c3.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120296);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_xref(name:"FEDORA", value:"2018-24d1e5a2c3");

  script_name(english:"Fedora 29 : roundcubemail (2018-24d1e5a2c3)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**Version 1.3.8**

This is a service release to update the stable version 1.3 of
Roundcube Webmail. It contains fixes to several bugs backported from
the master branch including a security fix for a reported XSS
vulnerability plus updates to ensure compatibility with PHP 7.3 and
recent versions of Courier-IMAP, Dovecot and MySQL 8. See the complete
changelog below.

**Changelog**

  - Fix PHP warnings on dummy QUOTA responses in
    Courier-IMAP 4.17.1 (#6374)

  - Fix so fallback from BINARY to BODY FETCH is used also
    on [PARSE] errors in dovecot 2.3 (#6383)

  - Enigma: Fix deleting keys with authentication subkeys
    (#6381)

  - Fix invalid regular expressions that throw warnings on
    PHP 7.3 (#6398)

  - Fix so Classic skin splitter does not escape out of
    window (#6397)

  - Fix XSS issue in handling invalid style tag content
    (#6410)

  - Fix compatibility with MySQL 8 - error on 'system' table
    use

  - Managesieve: Fix bug where show_real_foldernames setting
    wasn't respected (#6422)

  - New_user_identity: Fix %fu/%u vars substitution in user
    specific LDAP params (#6419)

  - Fix support for 'allow-from <uri>' in 'x_frame_options'
    config option (#6449)

  - Fix bug where valid content between HTML comments could
    have been skipped in some cases (#6464)

  - Fix multiple VCard field search (#6466)

  - Fix session issue on long running requests (#6470)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-24d1e5a2c3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected roundcubemail package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:roundcubemail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:29");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^29([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 29", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC29", reference:"roundcubemail-1.3.8-1.fc29")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "roundcubemail");
}
