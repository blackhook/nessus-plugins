#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-4187.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(65749);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2013-1640", "CVE-2013-1652", "CVE-2013-1653", "CVE-2013-1654", "CVE-2013-1655", "CVE-2013-2275");
  script_bugtraq_id(58442, 58443, 58446, 58449, 58452, 58453);
  script_xref(name:"FEDORA", value:"2013-4187");

  script_name(english:"Fedora 17 : puppet-2.7.21-2.fc17 (2013-4187)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updates for the security announcements from Puppet Labs on
12-Mar-2013.

https://groups.google.com/group/puppet-announce/t/9200f268f8479e2c

This update also provides backported fixes for a number of issues with
ruby-1.9.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=919770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=919774"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=919775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=919783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=919784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=919785"
  );
  # https://groups.google.com/group/puppet-announce/t/9200f268f8479e2c
  script_set_attribute(
    attribute:"see_also",
    value:"https://groups.google.com/forum/#!topic/puppet-announce/kgDyaPhHniw"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-March/101161.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?43c541af"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected puppet package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:puppet");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:17");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/01");
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
if (! ereg(pattern:"^17([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 17.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC17", reference:"puppet-2.7.21-2.fc17")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "puppet");
}
