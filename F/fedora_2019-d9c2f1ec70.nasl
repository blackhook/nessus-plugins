#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-d9c2f1ec70.
#

include("compat.inc");

if (description)
{
  script_id(128580);
  script_version("1.3");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2019-10740", "CVE-2019-15237");
  script_xref(name:"FEDORA", value:"2019-d9c2f1ec70");

  script_name(english:"Fedora 29 : roundcubemail (2019-d9c2f1ec70)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**Version 1.3.10**

  - Managesieve: Fix so 'Create filter' option does not show
    up when Filters menu is disabled (#6723)

  - Enigma: Fix bug where revoked users/keys were not greyed
    out in key info

  - Enigma: Fix error message when trying to encrypt with a
    revoked key (#6607)

  - Enigma: Fix 'decryption oracle' bug [CVE-2019-10740]
    (#6638)

  - Fix compatibility with kolab/net_ldap3 > 1.0.7 (#6785)

  - Fix bug where bmp images couldn't be displayed on some
    systems (#6728)

  - Fix bug in parsing vCard data using PHP 7.3 due to an
    invalid regexp (#6744)

  - Fix bug where bold/strong text was converted to
    upper-case on html-to-text conversion (6758)

  - Fix bug in rcube_utils::parse_hosts() where %t, %d, %z
    could return only tld (#6746)

  - Fix bug where Next/Prev button in mail view didn't work
    with multi-folder search result (#6793)

  - Fix bug where selection of columns on messages list
    wasn't working

  - Fix bug in converting multi-page Tiff images to Jpeg
    (#6824)

  - Fix wrong messages order after returning to a
    multi-folder search result (#6836)

  - Fix PHP 7.4 deprecation: implode() wrong parameter order
    (#6866)

  - Fix bug where it was possible to bypass the
    position:fixed CSS check in received messages (#6898)

  - Fix bug where some strict remote URIs in url() style
    were unintentionally blocked (#6899)

  - Fix bug where it was possible to bypass the CSS jail in
    HTML messages using :root pseudo-class (#6897)

  - Fix bug where it was possible to bypass href URI check
    with data:application/xhtml+xml URIs (#6896)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-d9c2f1ec70"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected roundcubemail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:roundcubemail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:29");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/09");
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
if (! preg(pattern:"^29([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 29", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC29", reference:"roundcubemail-1.3.10-1.fc29")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
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
