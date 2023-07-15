#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133452);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_name(english:"Virtuozzo 7 : readykernel-patch (VZA-2019-008)");
  script_summary(english:"Checks the readykernel output for the updated patch.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the vzkernel package and the
readykernel-patch installed, the Virtuozzo installation on the remote
host is affected by the following vulnerability :

  - It was discovered that a malicious user logged in to a
    Virtuozzo container could potentially overwrite the
    'vzctl' binary on the host. The attacker could replace
    executables in that container with symlinks to
    '/proc/self/exe'. After that, 'vzctl exec' called from
    the host to run one of such executables would try to
    run the host's 'vzctl' there instead. If the attacker
    managed to intercept that, they would be able to change
    the contents of the host's 'vzctl' binary. The issue is
    similar to CVE-2019-5736, but affects 'vzctl' rather
    than 'runc'.

Note that Tenable Network Security has extracted the preceding
description block directly from the Virtuozzo security advisory.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://virtuozzosupport.force.com/s/article/VZA-2019-008");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-37.30-72.0-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?78eafaff");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-40.4-72.0-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2de194e0");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-43.10-72.0-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?644727ce");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-46.7-72.0-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fef35233");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-48.2-72.0-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1ba11462");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-63.3-72.0-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c32b3bf8");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-64.7-72.0-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c9b43be6");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-73.24-72.0-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20f800a1");
  script_set_attribute(attribute:"solution", value:"Update the readykernel patch.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:readykernel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Virtuozzo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    "kernel","vzkernel-3.10.0-693.1.1.vz7.37.30",
    "patch","readykernel-patch-37.30-72.0-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-693.11.6.vz7.40.4",
    "patch","readykernel-patch-40.4-72.0-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-693.17.1.vz7.43.10",
    "patch","readykernel-patch-43.10-72.0-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-693.21.1.vz7.46.7",
    "patch","readykernel-patch-46.7-72.0-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-693.21.1.vz7.48.2",
    "patch","readykernel-patch-48.2-72.0-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-862.9.1.vz7.63.3",
    "patch","readykernel-patch-63.3-72.0-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-862.11.6.vz7.64.7",
    "patch","readykernel-patch-64.7-72.0-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-862.20.2.vz7.73.24",
    "patch","readykernel-patch-73.24-72.0-1.vl7"
  )
);
readykernel_execute_checks(checks:checks, severity:SECURITY_HOLE, release:"Virtuozzo-7");
