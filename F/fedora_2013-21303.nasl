#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-21303.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(71062);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_bugtraq_id(63171, 63231);
  script_xref(name:"FEDORA", value:"2013-21303");

  script_name(english:"Fedora 20 : drupal6-context-3.3-1.fc20 (2013-21303)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2013-4445/CVE-2013-4446

Context, a drupal module, which allows you to manage contextual
conditions and reactions for different portions of your site, was
found to have two severe security issues.

First issue is that the module allows execution of PHP code via
manipulation of a URL argument in a path used for AJAX operations when
running in a configuration without a json_decode function provided by
PHP or the PECL JSON library. The vulnerability is

This vulnerability is only exploitable on a server running a PHP
version prior to 5.2 that does not have the json library installed.

Second issue is that the module uses Drupal's token scheme to restrict
access to the json rendering of a block. This control mechanism is
insufficient as Drupal's token scheme is designed to provide security
between two different sessions (or a session and a non authenticated
user) and is not designed to provide security within a session. The
vulnerability is mitigated by needing blocks that have sensitive
information.

The suggested fix is to update Drupal6-context to 6.x-3.2 and
Drupal7-context to 7.x-3.0.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://seclists.org/fulldisclosure/2013/Oct/118
  script_set_attribute(
    attribute:"see_also",
    value:"https://seclists.org/fulldisclosure/2013/Oct/118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://drupal.org/node/2113317"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-November/122455.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?31c4611c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected drupal6-context package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:drupal6-context");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^20([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 20.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC20", reference:"drupal6-context-3.3-1.fc20")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "drupal6-context");
}
