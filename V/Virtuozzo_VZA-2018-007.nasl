#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106588);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id(
    "CVE-2018-5344"
  );

  script_name(english:"Virtuozzo 7 : readykernel-patch (VZA-2018-007)");
  script_summary(english:"Checks the readykernel output for the updated patch.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the vzkernel package and the
readykernel-patch installed, the Virtuozzo installation on the remote
host is affected by the following vulnerabilities :

  - It was found that release() operation for the loop
    devices had insufficient protection for the device
    structures against the accesses from the concurrent
    open() operations. A local attacker could use specially
    arranged concurrent operations with a loop device to
    cause a denial of service (kernel crash due to a
    use-after-free error).

  - It was discovered that some operations with files in a
    container could lead to denial of service on the host
    due to extensive memory consumption.

Note that Tenable Network Security has extracted the preceding
description block directly from the Virtuozzo security advisory.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://help.virtuozzo.com/customer/portal/articles/2919971");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-15.2-43.0-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f1339fbb");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-18.7-43.0-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf438ce5");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-20.18-43.0-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2bae18e8");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-30.10-43.0-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5368314e");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-30.15-43.0-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fdd28a57");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-33.22-43.0-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?340bce16");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-37.30-43.0-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7fba1bf8");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-40.4-43.0-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1157a8be");
  script_set_attribute(attribute:"solution", value:"Update the readykernel patch.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/05");

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
    "kernel","vzkernel-3.10.0-327.18.2.vz7.15.2",
    "patch","readykernel-patch-15.2-43.0-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-327.43.0.vz7.18.7",
    "patch","readykernel-patch-18.7-43.0-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-327.43.0.vz7.20.18",
    "patch","readykernel-patch-20.18-43.0-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-514.16.1.vz7.30.10",
    "patch","readykernel-patch-30.10-43.0-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-514.16.1.vz7.30.15",
    "patch","readykernel-patch-30.15-43.0-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-514.26.1.vz7.33.22",
    "patch","readykernel-patch-33.22-43.0-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-693.1.1.vz7.37.30",
    "patch","readykernel-patch-37.30-43.0-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-693.11.6.vz7.40.4",
    "patch","readykernel-patch-40.4-43.0-1.vl7"
  )
);
readykernel_execute_checks(checks:checks, severity:SECURITY_WARNING, release:"Virtuozzo-7");
