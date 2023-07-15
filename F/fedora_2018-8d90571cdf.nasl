#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-8d90571cdf.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120603);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2017-13693", "CVE-2017-13694", "CVE-2017-13695");
  script_xref(name:"FEDORA", value:"2018-8d90571cdf");

  script_name(english:"Fedora 28 : acpica-tools (2018-8d90571cdf)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security fix for CVE-2017-13693, CVE-2017-13694, CVE-2017-13695.

This provides fixes for the user space ACPICA tools only. Any kernel
updates are handled separately.

This update also includes the upgrade to the 20190209 version of the
upstream source. 

---------------------------------------- 09 February 2018. Summary of
changes for version 20180209 :

1) ACPICA kernel-resident subsystem :

Completed the final integration of the recent changes to Package
Object handling and the module-level AML code support. This allows
forward references from individual package elements when the package
object is declared from within module-level code blocks. Provides
compatibility with other ACPI implementations.

The new architecture for the AML module-level code has been completed
and is now the default for the ACPICA code. This new architecture
executes the module-level code in-line as the ACPI table is
loaded/parsed instead of the previous architecture which deferred this
code until after the table was fully loaded. This solves some ASL code
ordering issues and provides compatibility with other ACPI
implementations. At this time, there is an option to fallback to the
earlier architecture, but this support is deprecated and is planned to
be completely removed later this year.

Added a compile-time option to ignore AE_NOT_FOUND exceptions during
resolution of named reference elements within Package objects.
Although this is potentially a serious problem, it can generate a lot
of noise/errors on platforms whose firmware carries around a bunch of
unused Package objects. To disable these errors, define
ACPI_IGNORE_PACKAGE_RESOLUTION_ERRORS in the OS-specific header. All
errors are always reported for ACPICA applications such as AcpiExec.

Fixed a regression related to the explicit type-conversion AML
operators (ToXXXX). The regression was introduced early in 2017 but
was not seen until recently because these operators are not fully
supported by other ACPI implementations and are thus rarely used by
firmware developers. The operators are defined by the ACPI
specification to not implement the 'implicit result object
conversion'. The regression incorrectly introduced this object
conversion for the following explicit conversion operators :

  - ToInteger

  - ToString

  - ToBuffer

  - ToDecimalString

  - ToHexString

  - ToBCD

  - FromBCD

2) iASL Compiler/Disassembler and Tools :

iASL: Fixed a problem with the compiler constant folding feature as
related to the ToXXXX explicit conversion operators. These operators
do not support the 'implicit result object conversion' by definition.
Thus, ASL expressions that use these operators cannot be folded to a
simple Store operator because Store implements the implicit
conversion. This change uses the CopyObject operator for the ToXXXX
operator folding instead. CopyObject is defined to not implement
implicit result conversions and is thus appropriate for folding the
ToXXXX operators.

iASL: Changed the severity of an error condition to a simple warning
for the case where a symbol is declared both locally and as an
external symbol. This accommodates existing ASL code.

AcpiExec: The -ep option to enable the new architecture for
module-level code has been removed. It is replaced by the -dp option
which instead has the opposite effect: it disables the new
architecture (the default) and enables the legacy architecture. When
the legacy code is removed in the future, the -dp option will be
removed also.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-8d90571cdf"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected acpica-tools package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:acpica-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:28");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^28([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 28", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC28", reference:"acpica-tools-20180209-1.fc28")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "acpica-tools");
}
