#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-17049.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(80406);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2014-9220");
  script_bugtraq_id(71360);
  script_xref(name:"FEDORA", value:"2014-17049");

  script_name(english:"Fedora 21 : openvas-cli-1.3.1-1.fc21 / openvas-manager-5.0.7-1.fc21 / openvas-scanner-4.0.5-1.fc21 (2014-17049)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Bugfix release of Openvas-7

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1169169"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-January/147751.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a07dbdb4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-January/147752.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0e2fd85f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-January/147753.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?201bac45"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected openvas-cli, openvas-manager and / or
openvas-scanner packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openvas-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openvas-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openvas-scanner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:21");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^21([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 21.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC21", reference:"openvas-cli-1.3.1-1.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"openvas-manager-5.0.7-1.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"openvas-scanner-4.0.5-1.fc21")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openvas-cli / openvas-manager / openvas-scanner");
}
