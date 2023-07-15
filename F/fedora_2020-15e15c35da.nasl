#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-15e15c35da.
#

include("compat.inc");

if (description)
{
  script_id(142857);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/20");

  script_cve_id("CVE-2020-28032", "CVE-2020-28033", "CVE-2020-28034", "CVE-2020-28035", "CVE-2020-28036", "CVE-2020-28037", "CVE-2020-28038", "CVE-2020-28039", "CVE-2020-28040");
  script_xref(name:"FEDORA", value:"2020-15e15c35da");

  script_name(english:"Fedora 31 : wordpress (2020-15e15c35da)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"**WordPress 5.5.3 Maintenance Release**

This maintenance release fixes an issue introduced in WordPress 5.5.2
which makes it impossible to install WordPress on a brand new website
that does not have a database connection configured.

----

**WordPress 5.5.2 Security and Maintenance Release**

**Security Updates**

  - Props to Alex Concha of the WordPress Security Team for
    their work in hardening deserialization requests.

  - Props to David Binovec on a fix to disable spam embeds
    from disabled sites on a multisite network.

  - Thanks to Marc Montas from Sucuri for reporting an issue
    that could lead to XSS from global variables.

  - Thanks to Justin Tran who reported an issue surrounding
    privilege escalation in XML-RPC. He also found and
    disclosed an issue around privilege escalation around
    post commenting via XML-RPC.

  - Props to Omar Ganiev who reported a method where a DoS
    attack could lead to RCE.

  - Thanks to Karim El Ouerghemmi from RIPS who disclosed a
    method to store XSS in post slugs.

  - Thanks to Slavco for reporting, and confirmation from
    Karim El Ouerghemmi, a method to bypass protected meta
    that could lead to arbitrary file deletion.

  - Thanks to Erwan LR from WPScan who responsibly disclosed
    a method that could lead to CSRF.

  - And a special thanks to @zieladam who was integral in
    many of the releases and patches during this release.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-15e15c35da"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected wordpress package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-28037");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:31");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/12");
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
if (rpm_check(release:"FC31", reference:"wordpress-5.5.3-1.fc31")) flag++;


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
