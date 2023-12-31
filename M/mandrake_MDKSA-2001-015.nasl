#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2001:015. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(61889);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2001-0125");
  script_xref(name:"MDKSA", value:"2001:015");

  script_name(english:"Mandrake Linux Security Advisory : exmh (MDKSA-2001:015)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandrake Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"All versions of exmh prior to 2.3.1 use the /tmp directory for storing
temporary files. This was done in an insecure manner as exmh did not
check to ensure that nobody placed a symlink with the same name in
/tmp in the meantime and thus was vulnerable to a symlink attack. This
could lead to a malicious local user being able to overwrite any file
writable by the user executing exmh. These updated versions of exmh
now use /tmp/username unless TMPDIR or EXMHTMPDIR is set."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected exmh package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:exmh");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:6.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK6.0", reference:"exmh-2.0.2-8.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK6.1", reference:"exmh-2.0.3-8.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK7.0", reference:"exmh-2.1.1-5.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK7.1", reference:"exmh-2.1.1-5.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK7.2", reference:"exmh-2.2-4.1mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
