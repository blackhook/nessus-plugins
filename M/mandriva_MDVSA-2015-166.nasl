#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:166. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(82419);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-6497", "CVE-2014-9050", "CVE-2014-9328");
  script_xref(name:"MDVSA", value:"2015:166");

  script_name(english:"Mandriva Linux Security Advisory : clamav (MDVSA-2015:166)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated clamav packages fix security vulnerabilities :

ClamAV 0.98.6 is a maintenance release to fix some bugs, some of them
being security bugs :

Certain JavaScript files causes ClamAV to segfault when scanned with
the -a (list archived files) (CVE-2013-6497).

A heap buffer overflow was reported in ClamAV when scanning a
specially crafted y0da Crypter obfuscated PE file (CVE-2014-9050).

Fix a heap out of bounds condition with crafted Yoda's crypter files.
This issue was discovered by Felix Groebert of the Google Security
Team.

Fix a heap out of bounds condition with crafted mew packer files. This
issue was discovered by Felix Groebert of the Google Security Team.

Fix a heap out of bounds condition with crafted upx packer files. This
issue was discovered by Kevin Szkudlapski of Quarkslab.

Fix a heap out of bounds condition with crafted upack packer files.
This issue was discovered by Sebastian Andrzej Siewior
(CVE-2014-9328).

Compensate a crash due to incorrect compiler optimization when
handling crafted petite packer files. This issue was discovered by
Sebastian Andrzej Siewior."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0487.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2015-0056.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:clamav-db");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:clamav-milter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:clamd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64clamav-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64clamav6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"clamav-0.98.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"clamav-db-0.98.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"clamav-milter-0.98.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"clamd-0.98.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64clamav-devel-0.98.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64clamav6-0.98.6-1.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
