#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:140. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(82393);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-9293", "CVE-2014-9294", "CVE-2014-9295", "CVE-2014-9296", "CVE-2014-9297", "CVE-2014-9298");
  script_xref(name:"MDVSA", value:"2015:140");

  script_name(english:"Mandriva Linux Security Advisory : ntp (MDVSA-2015:140)");
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
"Updated ntp packages fix security vulnerabilities :

If no authentication key is defined in the ntp.conf file, a
cryptographically-weak default key is generated (CVE-2014-9293).

ntp-keygen before 4.2.7p230 uses a non-cryptographic random number
generator with a weak seed to generate symmetric keys (CVE-2014-9294).

A remote unauthenticated attacker may craft special packets that
trigger buffer overflows in the ntpd functions crypto_recv() (when
using autokey authentication), ctl_putdata(), and configure(). The
resulting buffer overflows may be exploited to allow arbitrary
malicious code to be executed with the privilege of the ntpd process
(CVE-2014-9295).

A section of code in ntpd handling a rare error is missing a return
statement, therefore processing did not stop when the error was
encountered. This situation may be exploitable by an attacker
(CVE-2014-9296).

Stephen Roettger of the Google Security Team, Sebastian Krahmer of the
SUSE Security Team and Harlan Stenn of Network Time Foundation
discovered that the length value in extension fields is not properly
validated in several code paths in ntp_crypto.c, which could lead to
information leakage or denial of service (CVE-2014-9297).

Stephen Roettger of the Google Security Team reported that ACLs based
on IPv6 ::1 (localhost) addresses can be bypassed (CVE-2014-9298).

The ntp package has been patched to fix these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0541.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2015-0063.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ntp, ntp-client and / or ntp-doc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ntp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ntp-doc");
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
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"ntp-4.2.6p5-16.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"ntp-client-4.2.6p5-16.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"ntp-doc-4.2.6p5-16.1.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
