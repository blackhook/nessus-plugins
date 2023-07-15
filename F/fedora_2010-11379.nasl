#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-11379.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(47813);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2010-0654", "CVE-2010-1205", "CVE-2010-1207", "CVE-2010-1210", "CVE-2010-1211", "CVE-2010-1212", "CVE-2010-1213", "CVE-2010-1215", "CVE-2010-2752", "CVE-2010-2753", "CVE-2010-2754");
  script_xref(name:"FEDORA", value:"2010-11379");

  script_name(english:"Fedora 13 : sunbird-1.0-0.26.b2pre.fc13 / thunderbird-3.1.1-1.fc13 (2010-11379)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to new upstream Thunderbird version 3.1.1, fixing multiple
security issues detailed in the upstream advisories:
http://www.mozilla.org/security/announce/ Update also includes sunbird
package rebuilt against new version of Thunderbird.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://www.mozilla.org/security/announce/
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=568231"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=608238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=615455"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=615456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=615463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=615464"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=615466"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=615471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=615472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=615474"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=615488"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-July/044487.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eb4e1982"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-July/044488.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?803bbecd"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sunbird and / or thunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:sunbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:13");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! ereg(pattern:"^13([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 13.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC13", reference:"sunbird-1.0-0.26.b2pre.fc13")) flag++;
if (rpm_check(release:"FC13", reference:"thunderbird-3.1.1-1.fc13")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sunbird / thunderbird");
}
