#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-14745.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(49663);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2010-3082");
  script_bugtraq_id(43116);
  script_xref(name:"FEDORA", value:"2010-14745");

  script_name(english:"Fedora 14 : Django-1.2.3-1.fc14 (2010-14745)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"' Today the Django team has released Django 1.2.3, which remedies
several issues with the recent 1.2.2 package.

This package corrects the following problems :

  - The patch applied for the security issue covered in
    Django 1.2.2 caused issues with non-ASCII responses
    using CSRF tokens. This has been remedied.

    - The patch also caused issues with some forms, most
      notably the user-editing forms in the Django
      administrative interface. This has been remedied.

    - The packaging manifest did not contain the full list
      of required files. This has been remedied. '

See: http://www.djangoproject.com/weblog/2010/sep/10/123/ See
http://www.djangoproject.com/weblog/2010/sep/08/security-release/

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://www.djangoproject.com/weblog/2010/sep/08/security-release/
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.djangoproject.com/weblog/2010/sep/08/security-release/"
  );
  # http://www.djangoproject.com/weblog/2010/sep/10/123/
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.djangoproject.com/weblog/2010/sep/10/123/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=632239"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-September/048237.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4f01dc97"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Django package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:Django");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:14");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^14([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 14.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC14", reference:"Django-1.2.3-1.fc14")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Django");
}
