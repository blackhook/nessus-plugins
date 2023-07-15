#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109922);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id(
    "CVE-2018-1000199",
    "CVE-2018-1087"
  );

  script_name(english:"Virtuozzo 7 : readykernel-patch (VZA-2018-030)");
  script_summary(english:"Checks the readykernel output for the updated patch.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the vzkernel package and the
readykernel-patch installed, the Virtuozzo installation on the remote
host is affected by the following vulnerabilities :

  - A flaw was found in how KVM handled exceptions
    delivered after Mov SS or Pop SS instructions have
    encountered a breakpoint. As a result, exceptions
    passed to the guest kernel could have wrong values on
    the stack. An unprivileged KVM guest user could use
    this flaw to crash the guest kernel or, potentially,
    escalate their privileges in the guest system.

  - The implementation of ptrace in the kernel does not
    handle errors correctly when working with the debug
    registers. As a result, the hardware breakpoints could
    become corrupted. An unprivileged user could exploit
    this flaw to crash the kernel resulting in a
    denial-of-service, or, potentially, to escalate their
    privileges in the system.

Note that Tenable Network Security has extracted the preceding
description block directly from the Virtuozzo security advisory.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://help.virtuozzo.com/customer/portal/articles/2939806");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-1000199");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-1087");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-20.18-51.1-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b27522be");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-30.10-51.1-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?73654fa9");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-30.15-51.1-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f2e37994");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-33.22-51.1-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb804d30");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-37.30-51.1-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?df964cee");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-40.4-51.1-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?042c4699");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-43.10-51.1-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?031366a4");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-46.7-51.1-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?55141bd5");
  script_set_attribute(attribute:"solution", value:"Update the readykernel patch.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:readykernel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Virtuozzo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Virtuozzo/release", "Host/Virtuozzo/rpm-list", "Host/readykernel-info");

  exit(0);
}

include("global_settings.inc");
include("readykernel.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/Virtuozzo/release");
if (isnull(release) || "Virtuozzo" >!< release) audit(AUDIT_OS_NOT, "Virtuozzo");
os_ver = pregmatch(pattern: "Virtuozzo Linux release ([0-9]+\.[0-9])(\D|$)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Virtuozzo");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Virtuozzo 7.x", "Virtuozzo " + os_ver);

if (!get_kb_item("Host/Virtuozzo/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Virtuozzo", cpu);

rk_info = get_kb_item("Host/readykernel-info");
if (empty_or_null(rk_info)) audit(AUDIT_UNKNOWN_APP_VER, "Virtuozzo");

checks = make_list2(
  make_array(
    "kernel","vzkernel-3.10.0-327.42.0.vz7.20.18",
    "patch","readykernel-patch-20.18-51.1-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-514.16.1.vz7.30.10",
    "patch","readykernel-patch-30.10-51.1-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-514.16.1.vz7.30.15",
    "patch","readykernel-patch-30.15-51.1-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-514.26.1.vz7.33.22",
    "patch","readykernel-patch-33.22-51.1-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-693.1.1.vz7.37.30",
    "patch","readykernel-patch-37.30-51.1-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-693.11.6.vz7.40.4",
    "patch","readykernel-patch-40.4-51.1-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-693.17.1.vz7.43.10",
    "patch","readykernel-patch-43.10-51.1-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-693.21.1.vz7.46.7",
    "patch","readykernel-patch-46.7-51.1-1.vl7"
  )
);
readykernel_execute_checks(checks:checks, severity:SECURITY_WARNING, release:"Virtuozzo-7");
