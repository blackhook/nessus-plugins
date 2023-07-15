##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0010. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160823);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id("CVE-2021-21381");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : flatpak Vulnerability (NS-SA-2022-0010)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has flatpak packages installed that are affected
by a vulnerability:

  - Flatpak is a system for building, distributing, and running sandboxed desktop applications on Linux. In
    Flatpack since version 0.9.4 and before version 1.10.2 has a vulnerability in the file forwarding
    feature which can be used by an attacker to gain access to files that would not ordinarily be allowed by
    the app's permissions. By putting the special tokens `@@` and/or `@@u` in the Exec field of a Flatpak
    app's .desktop file, a malicious app publisher can trick flatpak into behaving as though the user had
    chosen to open a target file with their Flatpak app, which automatically makes that file available to the
    Flatpak app. This is fixed in version 1.10.2. A minimal solution is the first commit `Disallow @@ and @@U
    usage in desktop files`. The follow-up commits `dir: Reserve the whole @@ prefix` and `dir: Refuse to
    export .desktop files with suspicious uses of @@ tokens` are recommended, but not strictly required. As a
    workaround, avoid installing Flatpak apps from untrusted sources, or check the contents of the exported
    `.desktop` files in `exports/share/applications/*.desktop` (typically
    `~/.local/share/flatpak/exports/share/applications/*.desktop` and
    `/var/lib/flatpak/exports/share/applications/*.desktop`) to make sure that literal filenames do not follow
    `@@` or `@@u`. (CVE-2021-21381)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0010");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-21381");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL flatpak packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21381");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:flatpak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:flatpak-builder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:flatpak-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:flatpak-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:flatpak-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:flatpak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:flatpak-builder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:flatpak-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:flatpak-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:flatpak-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.04': [
    'flatpak-1.0.9-11.el7_9',
    'flatpak-builder-1.0.0-11.el7_9',
    'flatpak-debuginfo-1.0.9-11.el7_9',
    'flatpak-devel-1.0.9-11.el7_9',
    'flatpak-libs-1.0.9-11.el7_9'
  ],
  'CGSL MAIN 5.04': [
    'flatpak-1.0.9-11.el7_9',
    'flatpak-builder-1.0.0-11.el7_9',
    'flatpak-debuginfo-1.0.9-11.el7_9',
    'flatpak-devel-1.0.9-11.el7_9',
    'flatpak-libs-1.0.9-11.el7_9'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'flatpak');
}
