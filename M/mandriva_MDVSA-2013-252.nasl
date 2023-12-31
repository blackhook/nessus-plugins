#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:252. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(70519);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2013-4319");
  script_bugtraq_id(62273);
  script_xref(name:"MDVSA", value:"2013:252");

  script_name(english:"Mandriva Linux Security Advisory : torque (MDVSA-2013:252)");
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
"Updated torque package fixes security vulnerability :

A non-priviledged user who was able to run jobs or login to a node
which ran pbs_server or pbs_mom, could submit arbitrary jobs to a
pbs_mom daemon to queue and run the job, which would run as root
(CVE-2013-4319)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2013-0308.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64torque-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64torque2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:torque");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:torque-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:torque-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:torque-mom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:torque-sched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:torque-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64torque-devel-4.1.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64torque2-4.1.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"torque-4.1.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"torque-client-4.1.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"torque-gui-4.1.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"torque-mom-4.1.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"torque-sched-4.1.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"torque-server-4.1.5.1-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
