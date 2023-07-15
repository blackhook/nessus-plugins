#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2317-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(128611);
  script_version("1.3");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2019-10136");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : SUSE Manager Client Tools (SUSE-SU-2019:2317-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the following issues :

golang-github-prometheus-prometheus :

Add support for Uyuni/SUSE Manager service discovery

  + Added 0003-Add-Uyuni-service-discovery

Readded _service file removed in error.

Update to 2.11.1

  + Bug Fix :

  - Fix potential panic when prometheus is watching multiple
    zookeeper paths.

Update to 2.11.0

  + Bug Fix :

  - resolve race condition in maxGauge.

  - Fix ZooKeeper connection leak.

  - Improved atomicity of .tmp block replacement during
    compaction for usual case.

  - Fix 'unknown series references' after clean shutdown.

  - Re-calculate block size when calling block.Delete.

  - Fix unsafe snapshots with head block.

  - prometheus_tsdb_compactions_failed_total is now
    incremented on any compaction failure.

  + Changes :

  - Remove max_retries from queue_config (it has been unused
    since rewriting remote-write to utilize the
    write-ahead-log)

  - The meta file BlockStats no longer holds size
    information. This is now dynamically calculated and kept
    in memory. It also includes the meta file size which was
    not included before

  - Renamed metric from
    prometheus_tsdb_wal_reader_corruption_errors to
    prometheus_tsdb_wal_reader_corruption_errors_total

  + Features :

  - Add option to use Alertmanager API v2.

  - Added humanizePercentage function for templates.

  - Include InitContainers in Kubernetes Service Discovery.

  - Provide option to compress WAL records using Snappy.

  + Enhancements :

  - Create new clean segment when starting the WAL.

  - Reduce allocations in PromQL aggregations.

  - Add storage warnings to LabelValues and LabelNames API
    results.

  - Add prometheus_http_requests_total metric.

  - Enable openbsd/arm build.

  - Remote-write allocation improvements.

  - Query performance improvement: Efficient iteration and
    search in HashForLabels and HashWithoutLabels.

  - Allow injection of arbitrary headers in promtool.

  - Allow passing external_labels in alert unit tests
    groups.

  - Allows globs for rules when unit testing.

  - Improved postings intersection matching.

  - Reduced disk usage for WAL for small setups.

  - Optimize queries using regexp for set lookups.

Rebase patch002-Default-settings.patch

Update to 2.10.0 :

  + Bug Fixes :

  - TSDB: Don't panic when running out of disk space and
    recover nicely from the condition

  - TSDB: Correctly handle empty labels.

  - TSDB: Don't crash on an unknown tombstone reference.

  - Storage/remote: Remove queue-manager specific metrics if
    queue no longer exists.

  - PromQL: Correctly display {__name__='a'}.

  - Discovery/kubernetes: Use service rather than ingress as
    the name for the service workqueue.

  - Discovery/azure: Don't panic on a VM with a public IP.

  - Web: Fixed Content-Type for js and css instead of using
    /etc/mime.types.

  - API: Encode alert values as string to correctly
    represent Inf/NaN.

  + Features :

  - Template expansion: Make external labels available as
    $externalLabels in alert and console template expansion.

  - TSDB: Add prometheus_tsdb_wal_segment_current metric for
    the WAL segment index that TSDB is currently writing to.
    tsdb

  - Scrape: Add scrape_series_added per-scrape metric. #5546

  + Enhancements

  - Discovery/kubernetes: Add labels
    __meta_kubernetes_endpoint_node_name and
    __meta_kubernetes_endpoint_hostname.

  - Discovery/azure: Add label
    __meta_azure_machine_public_ip.

  - TSDB: Simplify mergedPostings.Seek, resulting in better
    performance if there are many posting lists. tsdb

  - Log filesystem type on startup.

  - Cmd/promtool: Use POST requests for Query and
    QueryRange. client_golang

  - Web: Sort alerts by group name.

  - Console templates: Add convenience variables $rawParams,
    $params, $path.

Upadte to 2.9.2

  + Bug Fixes :

  - Make sure subquery range is taken into account for
    selection

  - Exhaust every request body before closing it

  - Cmd/promtool: return errors from rule evaluations

  - Remote Storage: string interner should not panic in
    release

  - Fix memory allocation regression in mergedPostings.Seek
    tsdb

Update to 2.9.1

  + Bug Fixes :

  - Discovery/kubernetes: fix missing label sanitization

  - Remote_write: Prevent reshard concurrent with calling
    stop

Update to 2.9.0

  + Feature :

  - Add honor_timestamps scrape option.

  + Enhancements :

  - Update Consul to support catalog.ServiceMultipleTags.

  - Discovery/kubernetes: add present labels for
    labels/annotations.

  - OpenStack SD: Add ProjectID and UserID meta labels.

  - Add GODEBUG and retention to the runtime page.

  - Add support for POSTing to /series endpoint.

  - Support PUT methods for Lifecycle and Admin APIs.

  - Scrape: Add global jitter for HA server.

  - Check for cancellation on every step of a range
    evaluation.

  - String interning for labels & values in the remote_write
    path.

  - Don't lose the scrape cache on a failed scrape.

  - Reload cert files from disk automatically. common

  - Use fixed length millisecond timestamp format for logs.
    common

  - Performance improvements for postings. Bug Fixes :

  - Remote Write: fix checkpoint reading.

  - Check if label value is valid when unmarshaling external
    labels from YAML.

  - Promparse: sort all labels when parsing.

  - Reload rules: copy state on both name and labels.

  - Exponentation operator to drop metric name in result of
    operation.

  - Config: resolve more file paths.

  - Promtool: resolve relative paths in alert test files.

  - Set TLSHandshakeTimeout in HTTP transport. common

  - Use fsync to be more resilient to machine crashes.

  - Keep series that are still in WAL in checkpoints.

Update to 2.8.1

  + Bug Fixes

  - Display the job labels in /targets which was removed
    accidentally

Update to 2.8.0

  + Change :

  - This release uses Write-Ahead Logging (WAL) for the
    remote_write API. This currently causes a slight
    increase in memory usage, which will be addressed in
    future releases.

  - Default time retention is used only when no size based
    retention is specified. These are flags where time
    retention is specified by the flag
    --storage.tsdb.retention and size retention by

    --storage.tsdb.retention.size.

  - prometheus_tsdb_storage_blocks_bytes_total is now
    prometheus_tsdb_storage_blocks_bytes.

  + Feature :

  - (EXPERIMENTAL) Time overlapping blocks are now allowed;
    vertical compaction and vertical query merge. It is an
    optional feature which is controlled by the
    --storage.tsdb.allow-overlapping-blocks flag, disabled
    by default.

  + Enhancements :

    &#9;- Use the WAL for remote_write API.

  - Query performance improvements.

  - UI enhancements with upgrade to Bootstrap 4.

  - Reduce time that Alertmanagers are in flux when
    reloaded.

  - Limit number of metrics displayed on UI to 10000.

  - (1) Remember All/Unhealthy choice on target-overview
    when reloading page. (2) Resize text-input area on Graph
    page on mouseclick.

  - In histogram_quantile merge buckets with equivalent le
    values.

  - Show list of offending labels in the error message in
    many-to-many scenarios.

  - Show Storage Retention criteria in effect on /status
    page.

  + Bug Fixes :

  + Fix sorting of rule groups.

  + Fix support for password_file and bearer_token_file in
    Kubernetes SD.

  + Scrape: catch errors when creating HTTP clients

  + Adds new metrics: prometheus_target_scrape_pools_total
    prometheus_target_scrape_pools_failed_total
    prometheus_target_scrape_pool_reloads_total
    prometheus_target_scrape_pool_reloads_failed_total

  + Fix panic when aggregator param is not a literal.

mgr-cfg: Ensure bytes type when using hashlib to avoid traceback
(bsc#1138822)

mgr-daemon: Fix systemd timer configuration on SLE12 (bsc#1142038)

mgr-osad: Fix obsolete for old osad packages, to allow installing
mgr-osad even by using osad at yum/zyppper install (bsc#1139453)

Ensure bytes type when using hashlib to avoid traceback (bsc#1138822)

mgr-virtualization: Fix missing python 3 ugettext (bsc#1138494)

Fix package dependencies to prevent file conflict (bsc#1143856)

rhnlib: Add SNI support for clients

Fix initialize ssl connection (bsc#1144155)

Fix bootstrapping SLE11SP4 trad client with SSL enabled (bsc#1148177)

spacecmd: Bugfix: referenced variable before assignment.

Bugfix: 'dict' object has no attribute 'iteritems' (bsc#1135881)

Add unit tests for custominfo, snippet, scap, ssm, cryptokey and
distribution

Fix missing runtime dependencies that made spacecmd return old
versions of packages in some cases, even if newer ones were available
(bsc#1148311)

spacewalk-backend: Do not overwrite comps and module data with older
versions

Fix issue with 'dists' keyword in url hostname

Import packages from all collections of a patch not just first one

Ensure bytes type when using hashlib to avoid traceback on XMLRPC call
to 'registration.register_osad' (bsc#1138822)

Fix reposync when dealing with RedHat CDN (bsc#1138358)

Fix for CVE-2019-10136. An attacker with a valid, but expired,
authenticated set of headers could move some digits around,
artificially extending the session validity without modifying the
checksum. (bsc#1136480)

Prevent FileNotFoundError: repomd.xml.key traceback (bsc#1137940)

Add journalctl output to spacewalk-debug tarballs

Prevent unnecessary triggering of channel-repodata tasks when GPG
signing is disabled (bsc#1137715)

Fix spacewalk-repo-sync for Ubuntu repositories in mirror case
(bsc#1136029)

Add support for ULN repositories on new Zypper based reposync.

Don't skip Deb package tags on package import (bsc#1130040)

For backend-libs subpackages, exclude files for the server (already
part of spacewalk-backend) to avoid conflicts (bsc#1148125)

prevent duplicate key violates on repo-sync with long changelog
entries (bsc#1144889)

spacewalk-remote-utils: Add RHEL8

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1130040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1135881"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1136029"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1136480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1137715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1137940"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1138313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1138358"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1138494"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1138822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1139453"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1142038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1143856"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1144155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1144889"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1148125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1148177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1148311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-10136/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192317-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?497610fc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Manager Tools 15:zypper in -t patch
SUSE-SLE-Manager-Tools-15-2019-2317=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2019-2317=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-2317=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:golang-github-prometheus-alertmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:golang-github-prometheus-prometheus");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", reference:"golang-github-prometheus-alertmanager-0.16.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"golang-github-prometheus-prometheus-2.11.1-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"golang-github-prometheus-alertmanager-0.16.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"golang-github-prometheus-prometheus-2.11.1-3.6.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "SUSE Manager Client Tools");
}
