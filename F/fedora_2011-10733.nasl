#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-10733.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56076);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2011-1831", "CVE-2011-1832", "CVE-2011-1834", "CVE-2011-1835", "CVE-2011-1837");
  script_xref(name:"FEDORA", value:"2011-10733");

  script_name(english:"Fedora 15 : ecryptfs-utils-90-1.fc15 (2011-10733)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - privilege escalation via mountpoint race conditions
    (CVE-2011-1831, CVE-2011-1832)

    - race condition when checking source during mount
      (CVE-2011-1833)

    - mtab corruption via improper handling (CVE-2011-1834)

    - key poisoning via insecure temp directory handling
      (CVE-2011-1835)

    - information disclosure via recovery mount in /tmp
      (CVE-2011-1836)

    - arbitrary file overwrite via lock counter race
      (CVE-2011-1837)

  - improve logging messages of ecryptfs pam module

    - keep own copy of passphrase, pam clears it too early

    - keyring from auth stack does not survive, use pam_data
      and delayed keyring initialization

    - keyring from auth stack does not survive, use pam_data
      and delayed keyring initialization

    - keyring from auth stack does not survive, use pam_data
      and delayed keyring initialization

    - improve logging messages of ecryptfs pam module

    - keep own copy of passphrase, pam clears it too early

    - keyring from auth stack does not survive, use pam_data
      and delayed keyring initialization

    - keyring from auth stack does not survive, use pam_data
      and delayed keyring initialization

    - keyring from auth stack does not survive, use pam_data
      and delayed keyring initialization

    - improve logging messages of ecryptfs pam module

    - keep own copy of passphrase, pam clears it too early

    - keyring from auth stack does not survive, use pam_data
      and delayed keyring initialization

    - keyring from auth stack does not survive, use pam_data
      and delayed keyring initialization

    - keyring from auth stack does not survive, use pam_data
      and delayed keyring initialization

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=729465"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-September/065042.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8d9e89ee"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ecryptfs-utils package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ecryptfs-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:15");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^15([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 15.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC15", reference:"ecryptfs-utils-90-1.fc15")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ecryptfs-utils");
}
