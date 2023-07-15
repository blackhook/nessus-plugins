#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-2a1a6a8432.
#

include("compat.inc");

if (description)
{
  script_id(137678);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/26");

  script_cve_id("CVE-2020-12641", "CVE-2020-13964", "CVE-2020-13965");
  script_xref(name:"FEDORA", value:"2020-2a1a6a8432");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/07/13");

  script_name(english:"Fedora 31 : roundcubemail (2020-2a1a6a8432)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"**RELEASE 1.4.6**

  - Installer: Fix regression in SMTP test section (#7417)

----

**RELEASE 1.4.5**

  - Fix bug in extracting required plugins from
    composer.json that led to spurious error in log (#7364)

  - Fix so the database setup description is compatible with
    MySQL 8 (#7340)

  - Markasjunk: Fix regression in jsevent driver (#7361)

  - Fix missing flag indication on collapsed thread in Larry
    and Elastic (#7366)

  - Fix default keyservers (use keys.openpgp.org), add note
    about CORS (#7373, #7367)

  - Password: Fix issue with Modoboa driver (#7372)

  - Mailvelope: Use sender's address to find pubkeys to
    check signatures (#7348)

  - Mailvelope: Fix Encrypt button hidden in Elastic (#7353)

  - Fix PHP warning: count(): Parameter must be an array or
    an object... in ID command handler (#7392)

  - Fix error when user-configured skin does not exist
    anymore (#7271)

  - Elastic: Fix aspect ratio of a contact photo in mail
    preview (#7339)

  - Fix bug where PDF attachments marked as inline could
    have not been attached on mail forward (#7382)

  - **Security**: Fix a couple of XSS issues in Installer
    (#7406)

  - **Security**: Fix XSS issue in template object
    'username' (#7406)

  - **Security**: Better fix for CVE-2020-12641

  - **Security**: Fix cross-site scripting (XSS) via
    malicious XML attachment

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-2a1a6a8432"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected roundcubemail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12641");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:roundcubemail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:31");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"FC31", reference:"roundcubemail-1.4.6-1.fc31")) flag++;


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
