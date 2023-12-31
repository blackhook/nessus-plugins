#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-13098.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43125);
  script_version("1.35");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2009-3080", "CVE-2009-4005", "CVE-2009-4031");
  script_bugtraq_id(32676, 33113, 35647, 35724, 35850, 35851, 36038, 36379, 36512, 36639, 36723, 36803, 36824, 36827, 36901, 37036, 37068);
  script_xref(name:"FEDORA", value:"2009-13098");

  script_name(english:"Fedora 10 : kernel-2.6.27.41-170.2.117.fc10 (2009-13098)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to kernel 2.6.27.41:
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.27.39
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.27.40
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.27.41

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.27.39
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f2cf410"
  );
  # http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.27.40
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?32fa246a"
  );
  # http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.27.41
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?17576cd1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=539414"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=539435"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=541160"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-December/032586.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eb4affcf"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel Sendpage Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^10([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 10.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC10", reference:"kernel-2.6.27.41-170.2.117.fc10")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
