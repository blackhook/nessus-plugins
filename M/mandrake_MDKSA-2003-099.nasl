#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2003:099. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(14081);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2003-0773", "CVE-2003-0774", "CVE-2003-0775", "CVE-2003-0776", "CVE-2003-0777", "CVE-2003-0778");
  script_xref(name:"MDKSA", value:"2003:099");

  script_name(english:"Mandrake Linux Security Advisory : sane (MDKSA-2003:099)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandrake Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in the saned daemon, a part of
the sane package, which allows for a scanner to be used remotely. The
IP address of the remote host is only checked after the first
communication occurs, which causes the saned.conf restrictions to be
ignored for the first connection. As well, a connection that is
dropped early can cause Denial of Service issues due to a number of
differing factors. Finally, a lack of error checking can cause various
other unfavourable actions.

The provided packages have been patched to correct the issues. sane,
as distributed in Mandrake Linux 9.1 and higher, have versions where
the fixes were applied upstream."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libsane1, libsane1-devel and / or sane-backends
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsane1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsane1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:sane-backends");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2021 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"libsane1-1.0.9-3.3.90mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"libsane1-devel-1.0.9-3.3.90mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"sane-backends-1.0.9-3.3.90mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
