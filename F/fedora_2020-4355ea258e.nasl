#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-4355ea258e.
#

include("compat.inc");

if (description)
{
  script_id(133113);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/29");

  script_cve_id("CVE-2019-13725", "CVE-2019-13726", "CVE-2019-13727", "CVE-2019-13728", "CVE-2019-13729", "CVE-2019-13730", "CVE-2019-13732", "CVE-2019-13734", "CVE-2019-13735", "CVE-2019-13736", "CVE-2019-13737", "CVE-2019-13738", "CVE-2019-13739", "CVE-2019-13740", "CVE-2019-13741", "CVE-2019-13742", "CVE-2019-13743", "CVE-2019-13744", "CVE-2019-13745", "CVE-2019-13746", "CVE-2019-13747", "CVE-2019-13748", "CVE-2019-13749", "CVE-2019-13750", "CVE-2019-13751", "CVE-2019-13752", "CVE-2019-13753", "CVE-2019-13754", "CVE-2019-13755", "CVE-2019-13756", "CVE-2019-13757", "CVE-2019-13758", "CVE-2019-13759", "CVE-2019-13761", "CVE-2019-13762", "CVE-2019-13763", "CVE-2019-13764", "CVE-2019-13767", "CVE-2020-6377");
  script_xref(name:"FEDORA", value:"2020-4355ea258e");

  script_name(english:"Fedora 30 : chromium (2020-4355ea258e)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Update to 79.0.3945.117. Fixes CVE-2020-6377.

----

Security fix for CVE-2019-13767.

----

Update to Chromium 79. Fixes the usual giant pile of bugs and security
issues. This time, the list is :

CVE-2019-13725 CVE-2019-13726 CVE-2019-13727 CVE-2019-13728
CVE-2019-13729 CVE-2019-13730 CVE-2019-13732 CVE-2019-13734
CVE-2019-13735 CVE-2019-13764 CVE-2019-13736 CVE-2019-13737
CVE-2019-13738 CVE-2019-13739 CVE-2019-13740 CVE-2019-13741
CVE-2019-13742 CVE-2019-13743 CVE-2019-13744 CVE-2019-13745
CVE-2019-13746 CVE-2019-13747 CVE-2019-13748 CVE-2019-13749
CVE-2019-13750 CVE-2019-13751 CVE-2019-13752 CVE-2019-13753
CVE-2019-13754 CVE-2019-13755 CVE-2019-13756 CVE-2019-13757
CVE-2019-13758 CVE-2019-13759 CVE-2019-13761 CVE-2019-13762
CVE-2019-13763

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-4355ea258e"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected chromium package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:30");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/21");
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
if (! preg(pattern:"^30([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 30", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC30", reference:"chromium-79.0.3945.117-1.fc30", allowmaj:TRUE)) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromium");
}
