#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0712-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(134697);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/23");

  script_cve_id("CVE-2019-10214");

  script_name(english:"SUSE SLES15 Security Update : skopeo (SUSE-SU-2020:0712-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for skopeo fixes the following issues :

Update to skopeo v0.1.41 (bsc#1165715) :

Bump github.com/containers/image/v5 from 5.2.0 to 5.2.1

Bump gopkg.in/yaml.v2 from 2.2.7 to 2.2.8

Bump github.com/containers/common from 0.0.7 to 0.1.4

Remove the reference to openshift/api

vendor github.com/containers/image/v5@v5.2.0

Manually update buildah to v1.13.1

add specific authfile options to copy (and sync) command.

Bump github.com/containers/buildah from 1.11.6 to 1.12.0

Add context to --encryption-key / --decryption-key processing failures

Bump github.com/containers/storage from 1.15.2 to 1.15.3

Bump github.com/containers/buildah from 1.11.5 to 1.11.6

remove direct reference on c/image/storage

Makefile: set GOBIN

Bump gopkg.in/yaml.v2 from 2.2.2 to 2.2.7

Bump github.com/containers/storage from 1.15.1 to 1.15.2

Introduce the sync command

openshift cluster: remove .docker directory on teardown

Bump github.com/containers/storage from 1.14.0 to 1.15.1

document installation via apk on alpine

Fix typos in doc for image encryption

Image encryption/decryption support in skopeo

make vendor-in-container

Bump github.com/containers/buildah from 1.11.4 to 1.11.5

Travis: use go v1.13

Use a Windows Nano Server image instead of Server Core for multi-arch
testing

Increase test timeout to 15 minutes

Run the test-system container without --net=host

Mount /run/systemd/journal/socket into test-system containers

Don't unnecessarily filter out vendor from (go list ./...) output

Use -mod=vendor in (go {list,test,vet})

Bump github.com/containers/buildah from 1.8.4 to 1.11.4

Bump github.com/urfave/cli from 1.20.0 to 1.22.1

skopeo: drop support for ostree

Don't critically fail on a 403 when listing tags

Revert 'Temporarily work around auth.json location confusion'

Remove references to atomic

Remove references to storage.conf

Dockerfile: use golang-github-cpuguy83-go-md2man

bump version to v0.1.41-dev

systemtest: inspect container image different from current platform
arch

Changes in v0.1.40: vendor containers/image v5.0.0

copy: add a --all/-a flag

System tests: various fixes

Temporarily work around auth.json location confusion

systemtest: copy: docker->storage->oci-archive

systemtest/010-inspect.bats: require only PATH

systemtest: add simple env test in inspect.bats

bash completion: add comments to keep scattered options in sync

bash completion: use read -r instead of disabling SC2207

bash completion: support --opt arg completion

bash-completion: use replacement instead of sed

bash completion: disable shellcheck SC2207

bash completion: double-quote to avoid re-splitting

bash completions: use bash replacement instead of sed

bash completion: remove unused variable

bash-completions: split decl and assignment to avoid masking retvals

bash completion: double-quote fixes

bash completion: hard-set PROG=skopeo

bash completion: remove unused variable

bash completion: use `||` instead of `-o`

bash completion: rm eval on assigned variable

copy: add --dest-compress-format and --dest-compress-level

flag: add optionalIntValue

Makefile: use go proxy

inspect --raw: skip the NewImage() step

update OCI image-spec to 775207bd45b6cb8153ce218cc59351799217451f

inspect.go: inspect env variables

ostree: use both image and & storage buildtags

Update to skopeo v0.1.39 (bsc#1159530): inspect: add a --config flag

Add --no-creds flag to skopeo inspect

Add --quiet option to skopeo copy

New progress bars

Parallel Pulls and Pushes for major speed improvements

containers/image moved to a new progress-bar library to fix various
issues related to overlapping bars and redundant entries.

enforce blocking of registries

Allow storage-multiple-manifests

When copying images and the output is not a tty (e.g., when piping to
a file) print single lines instead of using progress bars. This avoids
long and hard to parse output

man pages: add --dest-oci-accept-uncompressed-layers

completions :

  - Introduce transports completions

  - Fix bash completions when a option requires a argument

  - Use only spaces in indent

  - Fix completions with a global option

  - add --dest-oci-accept-uncompressed-layers

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1159530"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1165715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-10214/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200712-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3b5c5e74"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Server Applications 15-SP1:zypper in
-t patch SUSE-SLE-Module-Server-Applications-15-SP1-2020-712=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:skopeo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:skopeo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"skopeo-0.1.41-4.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"skopeo-debuginfo-0.1.41-4.11.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "skopeo");
}
