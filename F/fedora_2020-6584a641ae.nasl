#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-6584a641ae.
#

include("compat.inc");

if (description)
{
  script_id(139260);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/06");

  script_cve_id("CVE-2020-3327", "CVE-2020-3350", "CVE-2020-3481");
  script_xref(name:"FEDORA", value:"2020-6584a641ae");

  script_name(english:"Fedora 32 : clamav (2020-6584a641ae)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"ClamAV 0.102.4 is a bug patch release to address the following 
issues :

CVE-2020-3350
<https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-3350> Fixed a
vulnerability a malicious user could exploit to replace a scan
target's directory with a symlink to another path to trick clamscan,
clamdscan, or clamonacc into removing or moving a different file (such
as a critical system file). The issue would affect users that use the
--move or --remove options for clamscan, clamdscan and clamonacc.

For more information about AV quarantine attacks using links, see
RACK911 Lab's report
<https://www.rack911labs.com/research/exploiting-almost-every-antiviru
s-software>.

CVE-2020-3327
<https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-3327> Fixed a
vulnerability in the ARJ archive-parsing module in ClamAV 0.102.3 that
could cause a denial-of-service (DoS) condition. Improper bounds
checking resulted in an out-of-bounds read that could cause a crash.
The previous fix for this CVE in version 0.102.3 was incomplete. This
fix correctly resolves the issue.

CVE-2020-3481
<https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-3481> Fixed a
vulnerability in the EGG archive module in ClamAV 0.102.0 - 0.102.3
that could cause a denial-of-service (DoS) condition. Improper error
handling could cause a crash due to a NULL pointer dereference. This
vulnerability is mitigated for those using the official ClamAV
signature databases because the file type signatures in daily.cvd will
not enable the EGG archive parser in affected versions.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-6584a641ae"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected clamav package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3350");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:clamav");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:32");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/03");
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
if (! preg(pattern:"^32([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 32", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC32", reference:"clamav-0.102.4-1.fc32")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "clamav");
}
