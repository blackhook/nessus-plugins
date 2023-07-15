#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0238. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(132442);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id("CVE-2019-3827");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : gvfs Vulnerability (NS-SA-2019-0238)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has gvfs packages installed that are affected by a
vulnerability:

  - An incorrect permission check in the admin backend in
    gvfs before version 1.39.4 was found that allows reading
    and modify arbitrary files by privileged users without
    asking for password when no authentication agent is
    running. This vulnerability can be exploited by
    malicious programs running under privileges of users
    belonging to the wheel group to further escalate its
    privileges by modifying system files without user's
    knowledge. Successful exploitation requires uncommon
    system configuration. (CVE-2019-3827)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0238");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL gvfs packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3827");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.05": [
    "gvfs-1.36.2-3.el7",
    "gvfs-afc-1.36.2-3.el7",
    "gvfs-afp-1.36.2-3.el7",
    "gvfs-archive-1.36.2-3.el7",
    "gvfs-client-1.36.2-3.el7",
    "gvfs-debuginfo-1.36.2-3.el7",
    "gvfs-devel-1.36.2-3.el7",
    "gvfs-fuse-1.36.2-3.el7",
    "gvfs-goa-1.36.2-3.el7",
    "gvfs-gphoto2-1.36.2-3.el7",
    "gvfs-mtp-1.36.2-3.el7",
    "gvfs-smb-1.36.2-3.el7",
    "gvfs-tests-1.36.2-3.el7"
  ],
  "CGSL MAIN 5.05": [
    "gvfs-1.36.2-3.el7",
    "gvfs-afc-1.36.2-3.el7",
    "gvfs-afp-1.36.2-3.el7",
    "gvfs-archive-1.36.2-3.el7",
    "gvfs-client-1.36.2-3.el7",
    "gvfs-debuginfo-1.36.2-3.el7",
    "gvfs-devel-1.36.2-3.el7",
    "gvfs-fuse-1.36.2-3.el7",
    "gvfs-goa-1.36.2-3.el7",
    "gvfs-gphoto2-1.36.2-3.el7",
    "gvfs-mtp-1.36.2-3.el7",
    "gvfs-smb-1.36.2-3.el7",
    "gvfs-tests-1.36.2-3.el7"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gvfs");
}
