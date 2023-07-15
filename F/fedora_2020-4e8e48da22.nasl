#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-4e8e48da22.
#

include("compat.inc");

if (description)
{
  script_id(142955);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2020-15967", "CVE-2020-15968", "CVE-2020-15969", "CVE-2020-15970", "CVE-2020-15971", "CVE-2020-15972", "CVE-2020-15973", "CVE-2020-15974", "CVE-2020-15975", "CVE-2020-15976", "CVE-2020-15977", "CVE-2020-15978", "CVE-2020-15979", "CVE-2020-15980", "CVE-2020-15981", "CVE-2020-15982", "CVE-2020-15983", "CVE-2020-15984", "CVE-2020-15985", "CVE-2020-15986", "CVE-2020-15987", "CVE-2020-15988", "CVE-2020-15989", "CVE-2020-15990", "CVE-2020-15991", "CVE-2020-15992", "CVE-2020-16000", "CVE-2020-16001", "CVE-2020-16002", "CVE-2020-16003", "CVE-2020-16004", "CVE-2020-16005", "CVE-2020-16006", "CVE-2020-16008", "CVE-2020-16009", "CVE-2020-6557");
  script_xref(name:"FEDORA", value:"2020-4e8e48da22");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0124");

  script_name(english:"Fedora 33 : chromium (2020-4e8e48da22)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Update to 86.0.4240.183.

Fixes the following security issues: CVE-2020-16004 CVE-2020-16005
CVE-2020-16006 CVE-2020-16008 CVE-2020-16009

Also disables the very verbose output going to stdout.

----

Update to Chromium 86. A few big things here :

1. Upstream has made hardware accelerated video support (VAAPI) for
Linux possible without patches. One key difference is that the
patchset used previously in Fedora enabled it by default and
upstream's approach disables it by default. To enable Hardware
accelerated video in chromium, open this link in chromium :

chrome://flags/#enable-accelerated-video-decode

Be sure it is turned on. Note that not all GPUs are supported.

2. All the security fixes you expect with a major release:
CVE-2020-15967 CVE-2020-15968 CVE-2020-15969 CVE-2020-15970
CVE-2020-15971 CVE-2020-15972 CVE-2020-15990 CVE-2020-15991
CVE-2020-15973 CVE-2020-15974 CVE-2020-15975 CVE-2020-15976
CVE-2020-6557 CVE-2020-15977 CVE-2020-15978 CVE-2020-15979
CVE-2020-15980 CVE-2020-15981 CVE-2020-15982 CVE-2020-15983
CVE-2020-15984 CVE-2020-15985 CVE-2020-15986 CVE-2020-15987
CVE-2020-15992 CVE-2020-15988 CVE-2020-15989 CVE-2020-16000
CVE-2020-16001 CVE-2020-16002 CVE-2020-16003

3. Without bats acting as pollinators, agave and cacao plants would
struggle. That means that bats are responsible for tequila and
chocolate.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-4e8e48da22"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected chromium package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16009");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:33");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^33([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 33", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC33", reference:"chromium-86.0.4240.183-1.fc33", allowmaj:TRUE)) flag++;


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
