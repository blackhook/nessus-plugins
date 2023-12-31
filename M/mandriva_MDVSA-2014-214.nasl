#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:214. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79322);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2014-3635", "CVE-2014-3636", "CVE-2014-3637", "CVE-2014-3638", "CVE-2014-3639", "CVE-2014-7824");
  script_bugtraq_id(69829, 69831, 69832, 69833, 69834, 71012);
  script_xref(name:"MDVSA", value:"2014:214");

  script_name(english:"Mandriva Linux Security Advisory : dbus (MDVSA-2014:214)");
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
"Updated dbus packages fixes the following security issues :

Alban Crequy and Simon McVittie discovered several vulnerabilities in
the D-Bus message daemon :

On 64-bit platforms, file descriptor passing could be abused by local
users to cause heap corruption in dbus-daemon, leading to a crash, or
potentially to arbitrary code execution (CVE-2014-3635).

A denial-of-service vulnerability in dbus-daemon allowed local
attackers to prevent new connections to dbus-daemon, or disconnect
existing clients, by exhausting descriptor limits (CVE-2014-3636).

Malicious local users could create D-Bus connections to dbus-daemon
which could not be terminated by killing the participating processes,
resulting in a denial-of-service vulnerability (CVE-2014-3637).

dbus-daemon suffered from a denial-of-service vulnerability in the
code which tracks which messages expect a reply, allowing local
attackers to reduce the performance of dbus-daemon (CVE-2014-3638).

dbus-daemon did not properly reject malicious connections from local
users, resulting in a denial-of-service vulnerability (CVE-2014-3639).

The patch issued by the D-Bus maintainers for CVE-2014-3636 was based
on incorrect reasoning, and does not fully prevent the attack
described as CVE-2014-3636 part A, which is repeated below. Preventing
that attack requires raising the system dbus-daemon's RLIMIT_NOFILE
(ulimit -n) to a higher value.

By queuing up the maximum allowed number of fds, a malicious sender
could reach the system dbus-daemon's RLIMIT_NOFILE (ulimit -n,
typically 1024 on Linux). This would act as a denial of service in two
ways :

  - new clients would be unable to connect to the
    dbus-daemon

    - when receiving a subsequent message from a
      non-malicious client that contained a fd, dbus-daemon
      would receive the MSG_CTRUNC flag, indicating that the
      list of fds was truncated; kernel fd-passing APIs do
      not provide any way to recover from that, so
      dbus-daemon responds to MSG_CTRUNC by disconnecting
      the sender, causing denial of service to that sender.

This update also resolves the CVE-2014-7824 security vulnerability."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0395.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0457.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dbus-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dbus-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64dbus-1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64dbus-1_3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"dbus-1.4.16-7.5.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"dbus-doc-1.4.16-7.5.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"dbus-x11-1.4.16-7.5.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64dbus-1-devel-1.4.16-7.5.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64dbus-1_3-1.4.16-7.5.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
