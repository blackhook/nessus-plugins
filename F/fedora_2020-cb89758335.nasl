#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-cb89758335.
#

include("compat.inc");

if (description)
{
  script_id(133017);
  script_version("1.1");
  script_cvs_date("Date: 2020/01/17");

  script_xref(name:"FEDORA", value:"2020-cb89758335");

  script_name(english:"Fedora 30 : phpMyAdmin (2020-cb89758335)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**Version 4.9.4** (2020-01-07)

  - issue #15724 Fix 2FA was disabled by a bug

  - issue [security] Fix SQL injection vulnerability on the
    user accounts page (PMASA-2020-1)

----

**Version 4.9.3** (2019-12-26)

  - issue #15570 Fix page contents go underneath of floating
    menubar in some cases

  - issue #15591 Fix php notice 'Undefined index:
    foreign_keys_data' on relations view when the user has
    column access

  - issue #15592 Fix php warning 'error_reporting() has been
    disabled for security reasons'

  - issue #15434 Fix middle click on table sort column name
    shows a blank page

  - issue Fix php notice 'Undefined index table_create_time'
    when setting displayed columns on results of a view

  - issue #15571 Fix fatal error when trying to edit row
    with row checked and button under the table

  - issue #15633 Fix designer set display field broken for
    php 5.x versions

  - issue #15621 Support CloudFront-Forwarded-Proto header
    for Amazon CloudFront proxy

  - issue Fix php 8.0 php notices - Undefined index on login
    page

  - issue #15640 Fix php 7.4 error when trying to access
    array offset on value of type null on table browse

  - issue #15641 Fix replication actions where broken (start
    slave, stop slave, reset, ...)

  - issue #15608 Fix DisableIS is broken when with
    controluser configured (database list broken)

  - issue #15614 Fix undefined offset on index page for
    MySQL 5.7.8 (server charset)

  - issue #15692 Fix JavaScript error when user has not
    enough privilege to view query statistics.

  - issue #14248 Fixed date selection in search menu missing
    higher Z-index value

  - issue Fix Uncaught php TypeError on php 8.0 when adding
    a column to table create form

  - issue #15682 Fix calendar not taking current time as
    default value

  - issue #15636 Fix php error trying to access array offset
    on value o type null on replication GUI

  - issue #15695 Fix input field for the time in datetime
    picker is disabled

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-cb89758335"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected phpMyAdmin package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:30");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/17");
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
if (rpm_check(release:"FC30", reference:"phpMyAdmin-4.9.4-1.fc30")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "phpMyAdmin");
}
