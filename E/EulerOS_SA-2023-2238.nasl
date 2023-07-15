#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177142);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/13");

  script_cve_id(
    "CVE-2022-23521",
    "CVE-2022-29187",
    "CVE-2022-39260",
    "CVE-2022-41903"
  );

  script_name(english:"EulerOS Virtualization 3.0.6.0 : git (EulerOS-SA-2023-2238)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the git packages installed, the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

  - Git is distributed revision control system. gitattributes are a mechanism to allow defining attributes for
    paths. These attributes can be defined by adding a `.gitattributes` file to the repository, which contains
    a set of file patterns and the attributes that should be set for paths matching this pattern. When parsing
    gitattributes, multiple integer overflows can occur when there is a huge number of path patterns, a huge
    number of attributes for a single pattern, or when the declared attribute names are huge. These overflows
    can be triggered via a crafted `.gitattributes` file that may be part of the commit history. Git silently
    splits lines longer than 2KB when parsing gitattributes from a file, but not when parsing them from the
    index. Consequentially, the failure mode depends on whether the file exists in the working tree, the index
    or both. This integer overflow can result in arbitrary heap reads and writes, which may result in remote
    code execution. The problem has been patched in the versions published on 2023-01-17, going back to
    v2.30.7. Users are advised to upgrade. There are no known workarounds for this issue. (CVE-2022-23521)

  - Git is a distributed revision control system. Git prior to versions 2.37.1, 2.36.2, 2.35.4, 2.34.4,
    2.33.4, 2.32.3, 2.31.4, and 2.30.5, is vulnerable to privilege escalation in all platforms. An
    unsuspecting user could still be affected by the issue reported in CVE-2022-24765, for example when
    navigating as root into a shared tmp directory that is owned by them, but where an attacker could create a
    git repository. Versions 2.37.1, 2.36.2, 2.35.4, 2.34.4, 2.33.4, 2.32.3, 2.31.4, and 2.30.5 contain a
    patch for this issue. The simplest way to avoid being affected by the exploit described in the example is
    to avoid running git as root (or an Administrator in Windows), and if needed to reduce its use to a
    minimum. While a generic workaround is not possible, a system could be hardened from the exploit described
    in the example by removing any such repository if it exists already and creating one as root to block any
    future attacks. (CVE-2022-29187)

  - Git is an open source, scalable, distributed revision control system. `git shell` is a restricted login
    shell that can be used to implement Git's push/pull functionality via SSH. In versions prior to 2.30.6,
    2.31.5, 2.32.4, 2.33.5, 2.34.5, 2.35.5, 2.36.3, and 2.37.4, the function that splits the command arguments
    into an array improperly uses an `int` to represent the number of entries in the array, allowing a
    malicious actor to intentionally overflow the return value, leading to arbitrary heap writes. Because the
    resulting array is then passed to `execv()`, it is possible to leverage this attack to gain remote code
    execution on a victim machine. Note that a victim must first allow access to `git shell` as a login shell
    in order to be vulnerable to this attack. This problem is patched in versions 2.30.6, 2.31.5, 2.32.4,
    2.33.5, 2.34.5, 2.35.5, 2.36.3, and 2.37.4 and users are advised to upgrade to the latest version.
    Disabling `git shell` access via remote logins is a viable short-term workaround. (CVE-2022-39260)

  - Git is distributed revision control system. `git log` can display commits in an arbitrary format using its
    `--format` specifiers. This functionality is also exposed to `git archive` via the `export-subst`
    gitattribute. When processing the padding operators, there is a integer overflow in
    `pretty.c::format_and_pad_commit()` where a `size_t` is stored improperly as an `int`, and then added as
    an offset to a `memcpy()`. This overflow can be triggered directly by a user running a command which
    invokes the commit formatting machinery (e.g., `git log --format=...`). It may also be triggered
    indirectly through git archive via the export-subst mechanism, which expands format specifiers inside of
    files within the repository during a git archive. This integer overflow can result in arbitrary heap
    writes, which may result in arbitrary code execution. The problem has been patched in the versions
    published on 2023-01-17, going back to v2.30.7. Users are advised to upgrade. Users who are unable to
    upgrade should disable `git archive` in untrusted repositories. If you expose git archive via `git
    daemon`, disable it by running `git config --global daemon.uploadArch false`. (CVE-2022-41903)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2238
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82691373");
  script_set_attribute(attribute:"solution", value:
"Update the affected git packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29187");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-41903");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:git-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:git-core-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl-Git");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "git-2.19.1-1.h15.eulerosv2r8",
  "git-core-2.19.1-1.h15.eulerosv2r8",
  "git-core-doc-2.19.1-1.h15.eulerosv2r8",
  "perl-Git-2.19.1-1.h15.eulerosv2r8"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "git");
}
