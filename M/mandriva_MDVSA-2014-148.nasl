#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:148. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76955);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2014-3532", "CVE-2014-3533");
  script_bugtraq_id(68337, 68339);
  script_xref(name:"MDVSA", value:"2014:148");

  script_name(english:"Mandriva Linux Security Advisory : dbus (MDVSA-2014:148)");
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
"Updated dbus packages fix security vulnerabilities :

A flaw was reported in D-Bus's file descriptor passing feature. A
local attacker could use this flaw to cause a service or application
to disconnect from the bus, typically resulting in that service or
application exiting (CVE-2014-3532).

A flaw was reported in D-Bus's file descriptor passing feature. A
local attacker could use this flaw to cause an invalid file descriptor
to be forwarded to a service or application, causing it to disconnect
from the bus, typically resulting in that service or application
exiting (CVE-2014-3533)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0294.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/01");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"dbus-1.4.16-6.4.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"dbus-doc-1.4.16-6.4.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"dbus-x11-1.4.16-6.4.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64dbus-1-devel-1.4.16-6.4.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64dbus-1_3-1.4.16-6.4.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
