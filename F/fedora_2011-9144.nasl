#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-9144.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(55604);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2011-2505", "CVE-2011-2506", "CVE-2011-2507", "CVE-2011-2508");
  script_bugtraq_id(48563);
  script_xref(name:"FEDORA", value:"2011-9144");

  script_name(english:"Fedora 14 : phpMyAdmin-3.4.3.1-1.fc14 (2011-9144)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Changes for 3.4.3.1 (2011-06-07)

  - [PMASA-2011-5] Possible session manipulation in Swekey
    authentication
    (http://www.phpmyadmin.net/home_page/security/PMASA-2011
    -5.php)

    - [PMASA-2011-6] Possible code injection in setup script
      in case session variables are compromised
      (http://www.phpmyadmin.net/home_page/security/PMASA-20
      11-6.php)

    - [PMASA-2011-7] Regular expression quoting issue in
      Synchronize code
      (http://www.phpmyadmin.net/home_page/security/PMASA-20
      11-7.php)

    - [PMASA-2011-8] Possible directory traversal
      (http://www.phpmyadmin.net/home_page/security/PMASA-20
      11-8.php)

Changes for 3.4.3.0 (2011-06-27)

  - [sync] Missing helper icons in Synchronize

    - [setup] Redefine a lable that was wrong

    - [parser] master is not a reserved word

    - [edit] Inline edit updates multiple duplicate rows

    - [edit] Inline edit does not escape backslashes

    - [interface] Columns class sometimes changed for
      nothing

    - [interface] Some tooltips do not disappear

    - [search] Fix search in non unicode tables

    - [display] Inline query edit broken

    - [privileges] Generate password option missing on new
      accounts

    - [edit] Inline edit places HTML line breaks in edit
      area

    - [interface] Inline query edit does not escape special
      characters

    - [security] minor XSS (require a valid token)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://www.phpmyadmin.net/home_page/security/PMASA-2011-5.php
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2011-5/"
  );
  # http://www.phpmyadmin.net/home_page/security/PMASA-2011-6.php
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2011-6/"
  );
  # http://www.phpmyadmin.net/home_page/security/PMASA-2011-7.php
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2011-7/"
  );
  # http://www.phpmyadmin.net/home_page/security/PMASA-2011-8.php
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2011-8/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=718964"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-July/062719.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f35faca3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected phpMyAdmin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Phpmyadmin 3.x RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:14");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"FC14", reference:"phpMyAdmin-3.4.3.1-1.fc14")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "phpMyAdmin");
}
