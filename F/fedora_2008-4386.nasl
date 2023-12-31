#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-4386.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(32461);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2007-1320");
  script_bugtraq_id(23731);
  script_xref(name:"FEDORA", value:"2008-4386");

  script_name(english:"Fedora 9 : kvm-65-7.fc9 (2008-4386)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Tue May 27 2008 Glauber Costa <gcosta at redhat.com> -
    65-7.fc9

    - Fix the build

    - Tue May 27 2008 Glauber Costa <gcosta at redhat.com> -
      65-6.fc9

    - Fix Cirrus heap overflow vulnerability (#448525)

    - Fri May 23 2008 Daniel P. Berrange <berrange at
      redhat.com> - 65-5.fc9

    - Put PTY in rawmode

    - Tue May 20 2008 Mark McLoughlin <markmc at redhat.com>
      - 65-4.fc9

    - Re-enable patch to fix -kernel with virtio/extboot
      drives (#444578)

    - Fri May 16 2008 Glauber Costa <gcosta at redhat.com> -
      65-3.fc9

    - Fix problem with cirrus device that was breaking vnc
      connections (rhbz #446830)

    - Tue Apr 29 2008 Mark McLoughlin <markmc at redhat.com>
      - 65-2

    - Fix -kernel with virtio/extboot drives (#444578)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=237342"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-May/010358.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?49e19dba"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected kvm package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kvm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:9");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 9.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC9", reference:"kvm-65-7.fc9")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kvm");
}
