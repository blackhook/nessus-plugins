#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:1970-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(138793);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2019-10215", "CVE-2019-15043", "CVE-2020-12245", "CVE-2020-13379");

  script_name(english:"SUSE SLES12 Security Update : SUSE Manager Client Tools (SUSE-SU-2020:1970-1)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update fixes the following issues :

cobbler :

Calculate relative path for kernel and inited when generating grub
entry (bsc#1170231) Added: fix-grub2-entry-paths.diff

Fix os-release version detection for SUSE Modified: sles15.patch

Jinja2 template library fix (bsc#1141661)

Removes string replace for textmode fix (bsc#1134195)

golang-github-prometheus-node_exporter :

Update to 0.18.1

  - [BUGFIX] Fix incorrect sysctl call in BSD meminfo
    collector, resulting in broken swap metrics on FreeBSD
    #1345

  - [BUGFIX] Fix rollover bug in mountstats collector #1364

  - Renamed interface label to device in netclass collector
    for consistency with

  - other network metrics #1224

  - The cpufreq metrics now separate the cpufreq and scaling
    data based on what the driver provides. #1248

  - The labels for the network_up metric have changed, see
    issue #1236

  - Bonding collector now uses mii_status instead of
    operstatus #1124

  - Several systemd metrics have been turned off by default
    to improve performance #1254

  - These include unit_tasks_current, unit_tasks_max,
    service_restart_total, and unit_start_time_seconds

  - The systemd collector blacklist now includes automount,
    device, mount, and slice units by default. #1255

  - [CHANGE] Bonding state uses mii_status #1124

  - [CHANGE] Add a limit to the number of in-flight requests
    #1166

  - [CHANGE] Renamed interface label to device in netclass
    collector #1224

  - [CHANGE] Add separate cpufreq and scaling metrics #1248

  - [CHANGE] Several systemd metrics have been turned off by
    default to improve performance #1254

  - [CHANGE] Expand systemd collector blacklist #1255

  - [CHANGE] Split cpufreq metrics into a separate collector
    #1253

  - [FEATURE] Add a flag to disable exporter metrics #1148

  - [FEATURE] Add kstat-based Solaris metrics for boottime,
    cpu and zfs collectors #1197

  - [FEATURE] Add uname collector for FreeBSD #1239

  - [FEATURE] Add diskstats collector for OpenBSD #1250

  - [FEATURE] Add pressure collector exposing pressure stall
    information for Linux #1174

  - [FEATURE] Add perf exporter for Linux #1274

  - [ENHANCEMENT] Add Infiniband counters #1120

  - [ENHANCEMENT] Add TCPSynRetrans to netstat default
    filter #1143

  - [ENHANCEMENT] Move network_up labels into new metric
    network_info #1236

  - [ENHANCEMENT] Use 64-bit counters for Darwin netstat

  - [BUGFIX] Add fallback for missing /proc/1/mounts #1172

  - [BUGFIX] Fix node_textfile_mtime_seconds to work
    properly on symlinks #1326

Add network-online (Wants and After) dependency to systemd unit
bsc#1143913

golang-github-prometheus-prometheus :

Update change log and spec file

  + Modified spec file: default to golang 1.14 to avoid
    'have choice' build issues in OBS.

  + Rebase and update patches for version 2.18.0

  + Changed :

  - 0002-Default-settings.patch Changed

Update to 2.18.0

  + Features

  - Tracing: Added experimental Jaeger support #7148

  + Changes

  - Federation: Only use local TSDB for federation (ignore
    remote read). #7096

  - Rules: `rule_evaluations_total` and
    `rule_evaluation_failures_total` have a `rule_group`
    label now. #7094

  + Enhancements

  - TSDB: Significantly reduce WAL size kept around after a
    block cut. #7098

  - Discovery: Add `architecture` meta label for EC2. #7000

  + Bug fixes

  - UI: Fixed wrong MinTime reported by /status. #7182

  - React UI: Fixed multiselect legend on OSX. #6880

  - Remote Write: Fixed blocked resharding edge case. #7122

  - Remote Write: Fixed remote write not updating on relabel
    configs change. #7073

Changes from 2.17.2

  + Bug fixes

  - Federation: Register federation metrics #7081

  - PromQL: Fix panic in parser error handling #7132

  - Rules: Fix reloads hanging when deleting a rule group
    that is being evaluated #7138

  - TSDB: Fix a memory leak when prometheus starts with an
    empty TSDB WAL #7135

  - TSDB: Make isolation more robust to panics in web
    handlers #7129 #7136

Changes from 2.17.1

  + Bug fixes

  - TSDB: Fix query performance regression that increased
    memory and CPU usage #7051

Changes from 2.17.0

  + Features

  - TSDB: Support isolation #6841

  - This release implements isolation in TSDB. API queries
    and recording rules are guaranteed to only see full
    scrapes and full recording rules. This comes with a
    certain overhead in resource usage. Depending on the
    situation, there might be some increase in memory usage,
    CPU usage, or query latency.

  + Enhancements

  - PromQL: Allow more keywords as metric names #6933

  - React UI: Add normalization of localhost URLs in targets
    page #6794

  - Remote read: Read from remote storage concurrently #6770

  - Rules: Mark deleted rule series as stale after a reload
    #6745

  - Scrape: Log scrape append failures as debug rather than
    warn #6852

  - TSDB: Improve query performance for queries that
    partially hit the head #6676

  - Consul SD: Expose service health as meta label #5313

  - EC2 SD: Expose EC2 instance lifecycle as meta label
    #6914

  - Kubernetes SD: Expose service type as meta label for K8s
    service role #6684

  - Kubernetes SD: Expose label_selector and field_selector
    #6807

  - Openstack SD: Expose hypervisor id as meta label #6962

  + Bug fixes

  - PromQL: Do not escape HTML-like chars in query log #6834
    #6795

  - React UI: Fix data table matrix values #6896

  - React UI: Fix new targets page not loading when using
    non-ASCII characters #6892

  - Remote read: Fix duplication of metrics read from remote
    storage with external labels #6967 #7018

  - Remote write: Register WAL watcher and live reader
    metrics for all remotes, not just the first one #6998

  - Scrape: Prevent removal of metric names upon relabeling
    #6891

  - Scrape: Fix 'superfluous response.WriteHeader call'
    errors when scrape fails under some circonstances #6986

  - Scrape: Fix crash when reloads are separated by two
    scrape intervals #7011

Changes from 2.16.0

  + Features

  - React UI: Support local timezone on /graph #6692

  - PromQL: add absent_over_time query function #6490

  - Adding optional logging of queries to their own file
    #6520

  + Enhancements

  - React UI: Add support for rules page and 'Xs ago'
    duration displays #6503

  - React UI: alerts page, replace filtering togglers tabs
    with checkboxes #6543

  - TSDB: Export metric for WAL write errors #6647

  - TSDB: Improve query performance for queries that only
    touch the most recent 2h of data. #6651

  - PromQL: Refactoring in parser errors to improve error
    messages #6634

  - PromQL: Support trailing commas in grouping opts #6480

  - Scrape: Reduce memory usage on reloads by reusing scrape
    cache #6670

  - Scrape: Add metrics to track bytes and entries in the
    metadata cache #6675

  - promtool: Add support for line-column numbers for
    invalid rules output #6533

  - Avoid restarting rule groups when it is unnecessary
    #6450

  + Bug fixes

  - React UI: Send cookies on fetch() on older browsers
    #6553

  - React UI: adopt grafana flot fix for stacked graphs
    #6603

  - React UI: broken graph page browser history so that back
    button works as expected #6659

  - TSDB: ensure compactionsSkipped metric is registered,
    and log proper error if one is returned from head.Init
    #6616

  - TSDB: return an error on ingesting series with duplicate
    labels #6664

  - PromQL: Fix unary operator precedence #6579

  - PromQL: Respect query.timeout even when we reach
    query.max-concurrency #6712

  - PromQL: Fix string and parentheses handling in engine,
    which affected React UI #6612

  - PromQL: Remove output labels returned by absent() if
    they are produced by multiple identical label matchers
    #6493

  - Scrape: Validate that OpenMetrics input ends with `#
    EOF` #6505

  - Remote read: return the correct error if configs can't
    be marshal'd to JSON #6622

  - Remote write: Make remote client `Store` use passed
    context, which can affect shutdown timing #6673

  - Remote write: Improve sharding calculation in cases
    where we would always be consistently behind by tracking
    pendingSamples #6511

  - Ensure prometheus_rule_group metrics are deleted when a
    rule group is removed #6693

Changes from 2.15.2

  + Bug fixes

  - TSDB: Fixed support for TSDB blocks built with
    Prometheus before 2.1.0. #6564

  - TSDB: Fixed block compaction issues on Windows. #6547

Changes from 2.15.1

  + Bug fixes

  - TSDB: Fixed race on concurrent queries against same
    data. #6512

Changes from 2.15.0

  + Features

  - API: Added new endpoint for exposing per metric metadata
    `/metadata`. #6420 #6442

  + Changes

  - Discovery: Removed `prometheus_sd_kubernetes_cache_*`
    metrics. Additionally
    `prometheus_sd_kubernetes_workqueue_latency_seconds` and
    `prometheus_sd_kubernetes_workqueue_work_duration_second
    s` metrics now show correct values in seconds. #6393

  - Remote write: Changed `query` label on
    `prometheus_remote_storage_*` metrics to `remote_name`
    and `url`. #6043

  + Enhancements

  - TSDB: Significantly reduced memory footprint of loaded
    TSDB blocks. #6418 #6461

  - TSDB: Significantly optimized what we buffer during
    compaction which should result in lower memory footprint
    during compaction. #6422 #6452 #6468 #6475

  - TSDB: Improve replay latency. #6230

  - TSDB: WAL size is now used for size based retention
    calculation. #5886

  - Remote read: Added query grouping and range hints to the
    remote read request #6401

  - Remote write: Added
    `prometheus_remote_storage_sent_bytes_total` counter per
    queue. #6344

  - promql: Improved PromQL parser performance. #6356

  - React UI: Implemented missing pages like `/targets`
    #6276, TSDB status page #6281 #6267 and many other fixes
    and performance improvements.

  - promql: Prometheus now accepts spaces between time range
    and square bracket. e.g `[ 5m]` #6065

  + Bug fixes

  - Config: Fixed alertmanager configuration to not miss
    targets when configurations are similar. #6455

  - Remote write: Value of
    `prometheus_remote_storage_shards_desired` gauge shows
    raw value of desired shards and it's updated correctly.
    #6378

  - Rules: Prometheus now fails the evaluation of rules and
    alerts where metric results collide with labels
    specified in `labels` field. #6469

  - API: Targets Metadata API `/targets/metadata` now
    accepts empty `match_targets` parameter as in the spec.
    #6303

Changes from 2.14.0

  + Features

  - API: `/api/v1/status/runtimeinfo` and
    `/api/v1/status/buildinfo` endpoints added for use by
    the React UI. #6243

  - React UI: implement the new experimental React based UI.
    #5694 and many more

  - Can be found by under `/new`.

  - Not all pages are implemented yet.

  - Status: Cardinality statistics added to the Runtime &
    Build Information page. #6125

  + Enhancements

  - Remote write: fix delays in remote write after a
    compaction. #6021

  - UI: Alerts can be filtered by state. #5758

  + Bug fixes

  - Ensure warnings from the API are escaped. #6279

  - API: lifecycle endpoints return 403 when not enabled.
    #6057

  - Build: Fix Solaris build. #6149

  - Promtool: Remove false duplicate rule warnings when
    checking rule files with alerts. #6270

  - Remote write: restore use of deduplicating logger in
    remote write. #6113

  - Remote write: do not reshard when unable to send
    samples. #6111

  - Service discovery: errors are no longer logged on
    context cancellation. #6116, #6133

  - UI: handle null response from API properly. #6071

Changes from 2.13.1

  + Bug fixes

  - Fix panic in ARM builds of Prometheus. #6110

  - promql: fix potential panic in the query logger. #6094

  - Multiple errors of http: superfluous
    response.WriteHeader call in the logs. #6145

Changes from 2.13.0

  + Enhancements

  - Metrics: renamed prometheus_sd_configs_failed_total to
    prometheus_sd_failed_configs and changed to Gauge #5254

  - Include the tsdb tool in builds. #6089

  - Service discovery: add new node address types for
    kubernetes. #5902

  - UI: show warnings if query have returned some warnings.
    #5964

  - Remote write: reduce memory usage of the series cache.
    #5849

  - Remote read: use remote read streaming to reduce memory
    usage. #5703

  - Metrics: added metrics for remote write max/min/desired
    shards to queue manager. #5787

  - Promtool: show the warnings during label query. #5924

  - Promtool: improve error messages when parsing bad rules.
    #5965

  - Promtool: more promlint rules. #5515

  + Bug fixes

  - UI: Fix a Stored DOM XSS vulnerability with query
    history

[CVE-2019-10215](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-201
9-102 15). #6098

  - Promtool: fix recording inconsistency due to duplicate
    labels. #6026

  - UI: fixes service-discovery view when accessed from
    unhealthy targets. #5915

  - Metrics format: OpenMetrics parser crashes on short
    input. #5939

  - UI: avoid truncated Y-axis values. #6014

Changes from 2.12.0

  + Features

  - Track currently active PromQL queries in a log file.
    #5794

  - Enable and provide binaries for `mips64` / `mips64le`
    architectures. #5792

  + Enhancements

  - Improve responsiveness of targets web UI and API
    endpoint. #5740

  - Improve remote write desired shards calculation. #5763

  - Flush TSDB pages more precisely. tsdb#660

  - Add `prometheus_tsdb_retention_limit_bytes` metric.
    tsdb#667

  - Add logging during TSDB WAL replay on startup. tsdb#662

  - Improve TSDB memory usage. tsdb#653, tsdb#643, tsdb#654,
    tsdb#642, tsdb#627

  + Bug fixes

  - Check for duplicate label names in remote read. #5829

  - Mark deleted rules' series as stale on next evaluation.
    #5759

  - Fix JavaScript error when showing warning about
    out-of-sync server time. #5833

  - Fix `promtool test rules` panic when providing empty
    `exp_labels`. #5774

  - Only check last directory when discovering checkpoint
    number. #5756

  - Fix error propagation in WAL watcher helper functions.
    #5741

  - Correctly handle empty labels from alert templates.
    #5845

Update Uyuni/SUSE Manager service discovery patch

  + Modified 0003-Add-Uyuni-service-discovery.patch :

  + Adapt service discovery to the new Uyuni API endpoints

  + Modified spec file: force golang 1.12 to fix build
    issues in SLE15SP2

Update to Prometheus 2.11.2

grafana :

Update to version 7.0.3

  - Features / Enhancements

  - Stats: include all fields. #24829, @ryantxu

  - Variables: change VariableEditorList row action Icon to
    IconButton. #25217, @hshoff

  - Bug fixes

  - Cloudwatch: Fix dimensions of DDoSProtection. #25317,
    @papagian

  - Configuration: Fix env var override of sections
    containing hyphen. #25178, @marefr

  - Dashboard: Get panels in collapsed rows. #25079,
    @peterholmberg

  - Do not show alerts tab when alerting is disabled.
    #25285, @dprokop

  - Jaeger: fixes cascader option label duration value.
    #25129, @Estrax

  - Transformations: Fixed Transform tab crash & no update
    after adding first transform. #25152, @torkelo

Update to version 7.0.2

  - Bug fixes

  - Security: Urgent security patch release to fix
    CVE-2020-13379

Update to version 7.0.1

  - Features / Enhancements

  - Datasource/CloudWatch: Makes CloudWatch Logs query
    history more readable. #24795, @kaydelaney

  - Download CSV: Add date and time formatting. #24992,
    @ryantxu

  - Table: Make last cell value visible when right aligned.
    #24921, @peterholmberg

  - TablePanel: Adding sort order persistance. #24705,
    @torkelo

  - Transformations: Display correct field name when using
    reduce transformation. #25068, @peterholmberg

  - Transformations: Allow custom number input for binary
    operations. #24752, @ryantxu

  - Bug fixes

  - Dashboard/Links: Fixes dashboard links by tags not
    working. #24773, @KamalGalrani

  - Dashboard/Links: Fixes open in new window for dashboard
    link. #24772, @KamalGalrani

  - Dashboard/Links: Variables are resolved and limits to
    100. #25076, @hugohaggmark

  - DataLinks: Bring back variables interpolation in title.
    #24970, @dprokop

  - Datasource/CloudWatch: Field suggestions no longer
    limited to prefix-only. #24855, @kaydelaney

  - Explore/Table: Keep existing field types if possible.
    #24944, @kaydelaney

  - Explore: Fix wrap lines toggle for results of queries
    with filter expression. #24915, @ivanahuckova

  - Explore: fix undo in query editor. #24797, @zoltanbedi

  - Explore: fix word break in type head info. #25014,
    @zoltanbedi

  - Graph: Legend decimals now work as expected. #24931,
    @torkelo

  - LoginPage: Fix hover color for service buttons. #25009,
    @tskarhed

  - LogsPanel: Fix scrollbar. #24850, @ivanahuckova

  - MoveDashboard: Fix for moving dashboard caused all
    variables to be lost. #25005, @torkelo

  - Organize transformer: Use display name in field order
    comparer. #24984, @dprokop

  - Panel: shows correct panel menu items in view mode.
    #24912, @hugohaggmark

  - PanelEditor Fix missing labels and description if there
    is only single option in category. #24905, @dprokop

  - PanelEditor: Overrides name matcher still show all
    original field names even after Field default display
    name is specified. #24933, @torkelo

  - PanelInspector: Makes sure Data display options are
    visible. #24902, @hugohaggmark

  - PanelInspector: Hides unsupported data display options
    for Panel type. #24918, @hugohaggmark

  - PanelMenu: Make menu disappear on button press. #25015,
    @tskarhed

  - Postgres: Fix add button. #25087, @phemmer

  - Prometheus: Fix recording rules expansion. #24977,
    @ivanahuckova

  - Stackdriver: Fix creating Service Level Objectives (SLO)
    datasource query variable. #25023, @papagian

Update to version 7.0.0

  - Breaking changes

  - Removed PhantomJS: PhantomJS was deprecated in Grafana
    v6.4 and starting from Grafana v7.0.0, all PhantomJS
    support has been removed. This means that Grafana no
    longer ships with a built-in image renderer, and we
    advise you to install the Grafana Image Renderer plugin.

  - Dashboard: A global minimum dashboard refresh interval
    is now enforced and defaults to 5 seconds.

  - Interval calculation: There is now a new option Max data
    points that controls the auto interval $__interval
    calculation. Interval was previously calculated by
    dividing the panel width by the time range. With the new
    max data points option it is now easy to set $__interval
    to a dynamic value that is time range agnostic. For
    example if you set Max data points to 10 Grafana will
    dynamically set $__interval by dividing the current time
    range by 10.

  - Datasource/Loki: Support for deprecated Loki endpoints
    has been removed.

  - Backend plugins: Grafana now requires backend plugins to
    be signed, otherwise Grafana will not load/start them.
    This is an additional security measure to make sure
    backend plugin binaries and files haven't been tampered
    with. Refer to Upgrade Grafana for more information.

  - @grafana/ui: Forms migration notice, see @grafana/ui
    changelog

  - @grafana/ui: Select API change for creating custom
    values, see @grafana/ui changelog

  + Deprecation warnings

  - Scripted dashboards is now deprecated. The feature is
    not removed

but will be in a future release. We hope to address the underlying

requirement of dynamic dashboards in a different way. #24059

  - The unofficial first version of backend plugins together
    with

usage of grafana/grafana-plugin-model is now deprecated and support
for

that will be removed in a future release. Please refer to backend
plugins

documentation for information about the new officially supported
backend

plugins.

  - Features / Enhancements

  - Backend plugins: Log deprecation warning when using the
    unofficial first version of backend plugins. #24675,
    @marefr

  - Editor: New line on Enter, run query on Shift+Enter.
    #24654, @davkal

  - Loki: Allow multiple derived fields with the same name.
    #24437, @aocenas

  - Orgs: Add future deprecation notice. #24502, @torkelo

  - Bug Fixes

  - @grafana/toolkit: Use process.cwd() instead of PWD to
    get directory. #24677, @zoltanbedi

  - Admin: Makes long settings values line break in settings
    page. #24559, @hugohaggmark

  - Dashboard: Allow editing provisioned dashboard JSON and
    add confirmation when JSON is copied to dashboard.
    #24680, @dprokop

  - Dashboard: Fix for strange 'dashboard not found' errors
    when opening links in dashboard settings. #24416,
    @torkelo

  - Dashboard: Fix so default data source is selected when
    data source can't be found in panel editor. #24526,
    @mckn

  - Dashboard: Fixed issue changing a panel from transparent
    back to normal in panel editor. #24483, @torkelo

  - Dashboard: Make header names reflect the field name when
    exporting to CSV file from the the panel inspector.
    #24624, @peterholmberg

  - Dashboard: Make sure side pane is displayed with tabs by
    default in panel editor. #24636, @dprokop

  - Data source: Fix query/annotation help content
    formatting. #24687, @AgnesToulet

  - Data source: Fixes async mount errors. #24579, @Estrax

  - Data source: Fixes saving a data source without failure
    when URL doesn't specify a protocol. #24497, @aknuds1

  - Explore/Prometheus: Show results of instant queries only
    in table. #24508, @ivanahuckova

  - Explore: Fix rendering of react query editors. #24593,
    @ivanahuckova

  - Explore: Fixes loading more logs in logs context view.
    #24135, @Estrax

  - Graphite: Fix schema and dedupe strategy in rollup
    indicators for Metrictank queries. #24685, @torkelo

  - Graphite: Makes query annotations work again. #24556,
    @hugohaggmark

  - Logs: Clicking 'Load more' from context overlay doesn't
    expand log row. #24299, @kaydelaney

  - Logs: Fix total bytes process calculation. #24691,
    @davkal

  - Org/user/team preferences: Fixes so UI Theme can be set
    back to Default. #24628, @AgnesToulet

  - Plugins: Fix manifest validation. #24573, @aknuds1

  - Provisioning: Use proxy as default access mode in
    provisioning. #24669, @bergquist

  - Search: Fix select item when pressing enter and Grafana
    is served using a sub path. #24634, @tskarhed

  - Search: Save folder expanded state. #24496, @Clarity-89

  - Security: Tag value sanitization fix in OpenTSDB data
    source. #24539, @rotemreiss

  - Table: Do not include angular options in options when
    switching from angular panel. #24684, @torkelo

  - Table: Fixed persisting column resize for time series
    fields. #24505, @torkelo

  - Table: Fixes Cannot read property subRows of null.
    #24578, @hugohaggmark

  - Time picker: Fixed so you can enter a relative range in
    the time picker without being converted to absolute
    range. #24534, @mckn

  - Transformations: Make transform dropdowns not cropped.
    #24615, @dprokop

  - Transformations: Sort order should be preserved as
    entered by user when using the reduce transformation.
    #24494, @hugohaggmark

  - Units: Adds scale symbol for currencies with suffixed
    symbol. #24678, @hugohaggmark

  - Variables: Fixes filtering options with more than 1000
    entries. #24614, @hugohaggmark

  - Variables: Fixes so Textbox variables read value from
    url. #24623, @hugohaggmark

  - Zipkin: Fix error when span contains remoteEndpoint.
    #24524, @aocenas

  - SAML: Switch from email to login for user login
    attribute mapping (Enterprise)

Update Makefile and spec file

  - Remove phantomJS patch from Makefile

  - Fix multiline strings in Makefile

  - Exclude s390 from SLE12 builds, golang 1.14 is not built
    for s390

Add instructions for patching the Grafana JavaScript frontend.

BuildRequires golang(API) instead of go metapackage version range

  - BuildRequires: golang(API) >= 1.14 from BuildRequires: (
    go >= 1.14 with go < 1.15 )

Update to version 6.7.3

  - This version fixes bsc#1170557 and its corresponding
    CVE-2020-12245

  - Admin: Fix Synced via LDAP message for non-LDAP external
    users. #23477, @alexanderzobnin

  - Alerting: Fixes notifications for alerts with empty
    message in Google Hangouts notifier. #23559,
    @hugohaggmark

  - AuthProxy: Fixes bug where long username could not be
    cached.. #22926, @jcmcken

  - Dashboard: Fix saving dashboard when editing raw
    dashboard JSON model. #23314, @peterholmberg

  - Dashboard: Try to parse 8 and 15 digit numbers as
    timestamps if parsing of time range as date fails.
    #21694, @jessetan

  - DashboardListPanel: Fixed problem with empty panel after
    going into edit mode (General folder filter being
    automatically added) . #23426, @torkelo

  - Data source: Handle datasource withCredentials option
    properly. #23380, @hvtuananh

  - Security: Fix annotation popup XSS vulnerability.
    #23813, @torkelo

  - Server: Exit Grafana with status code 0 if no error.
    #23312, @aknuds1

  - TablePanel: Fix XSS issue in header column rename
    (backport). #23814, @torkelo

  - Variables: Fixes error when setting adhoc variable
    values. #23580, @hugohaggmark

Update to version 6.7.2: (see installed changelog for the full list of
changes)

  - BackendSrv: Adds config to response to fix issue for
    external plugins that used this property . #23032,
    @torkelo

  - Dashboard: Fixed issue with saving new dashboard after
    changing title . #23104, @dprokop

  - DataLinks: make sure we use the correct datapoint when
    dataset contains null value.. #22981, @mckn

  - Plugins: Fixed issue for plugins that imported dateMath
    util . #23069, @mckn

  - Security: Fix for dashboard snapshot original dashboard
    link could contain XSS vulnerability in url. #23254,
    @torkelo

  - Variables: Fixes issue with too many queries being
    issued for nested template variables after value change.
    #23220, @torkelo

  - Plugins: Expose promiseToDigest. #23249, @torkelo

  - Reporting (Enterprise): Fixes issue updating a report
    created by someone else

Update to 6.7.1: (see installed changelog for the full list of
changes) Bug Fixes

  - Azure: Fixed dropdowns not showing current value.
    #22914, @torkelo

  - BackendSrv: only add content-type on POST, PUT requests.
    #22910, @hugohaggmark

  - Panels: Fixed size issue with panel internal size when
    exiting panel edit mode. #22912, @torkelo

  - Reporting: fixes migrations compatibility with mysql
    (Enterprise)

  - Reporting: Reduce default concurrency limit to 4
    (Enterprise)

Update to 6.7.0: (see installed changelog for the full list of
changes) Bug Fixes

  - AngularPanels: Fixed inner height calculation for
    angular panels . #22796, @torkelo

  - BackendSrv: makes sure provided headers are correctly
    recognized and set. #22778, @hugohaggmark

  - Forms: Fix input suffix position (caret-down in Select)
    . #22780, @torkelo

  - Graphite: Fixed issue with query editor and next select
    metric now showing after selecting metric node . #22856,
    @torkelo

  - Rich History: UX adjustments and fixes. #22729,
    @ivanahuckova

Update to 6.7.0-beta1: Breaking changes

  - Slack: Removed Mention setting and instead introduce
    Mention Users, Mention Groups, and Mention Channel. The
    first two settings require user and group IDs,
    respectively. This change was necessary because the way
    of mentioning via the Slack API changed and mentions in
    Slack notifications no longer worked.

  - Alerting: Reverts the behavior of diff and percent_diff
    to not always be absolute. Something we introduced by
    mistake in 6.1.0. Alerting now support diff(),
    diff_abs(), percent_diff() and percent_diff_abs().
    #21338

  - Notice about changes in backendSrv for plugin authors In
    our mission to migrate away from AngularJS to React we
    have removed all AngularJS dependencies in the core data
    retrieval service backendSrv. Removing the AngularJS
    dependencies in backendSrv has the unfortunate side
    effect of AngularJS digest no longer being triggered for
    any request made with backendSrv. Because of this,
    external plugins using backendSrv directly may suffer
    from strange behaviour in the UI. To remedy this issue,
    as a plugin author you need to trigger the digest after
    a direct call to backendSrv. Bug Fixes API: Fix redirect
    issues. #22285, @papagian Alerting: Don't include
    image_url field with Slack message if empty. #22372,
    @aknuds1 Alerting: Fixed bad background color for
    default notifications in alert tab . #22660, @krvajal
    Annotations: In table panel when setting transform to
    annotation, they will now show up right away without a
    manual refresh. #22323, @krvajal Azure Monitor: Fix app
    insights source to allow for new __timeFrom and
    __timeTo. #21879, @ChadNedzlek BackendSrv: Fixes POST
    body for form data. gmark CloudWatch: Credentials cache
    invalidation fix. #22473, @sunker CloudWatch: Expand
    alias variables when query yields no result. #22695,
    @sunker Dashboard: Fix bug with NaN in alerting. #22053,
    @a-melnyk Explore: Fix display of multiline logs in log
    panel and explore. #22057, @thomasdraebing Heatmap:
    Legend color range is incorrect when using custom
    min/max. #21748, @sv5d Security: Fixed XSS issue in
    dashboard history diff . #22680, @torkelo StatPanel:
    Fixes base color is being used for null values . #22646,
    @torkelo

Update to version 6.6.2: (see installed changelog for the full list of
changes)

Update to version 6.6.1: (see installed changelog for the full list of
changes)

Update to version 6.6.0: (see installed changelog for the full list of
changes)

Update to version 6.5.3: (see installed changelog for the full list of
changes)

Update to version 6.5.2: (see installed changelog for the full list of
changes)

Update to version 6.5.1: (see installed changelog for the full list of
changes)

Update to version 6.5.0 (see installed changelog for the full list of
changes)

Update to version 6.4.5 :

  - Create version 6.4.5

  - CloudWatch: Fix high CPU load (#20579)

Add obs-service-go_modules to download required modules into
vendor.tar.gz

Adjusted spec file to use vendor.tar.gz

Adjusted Makefile to work with new filenames

BuildRequire go1.14

Update to version 6.4.4 :

  - DataLinks: Fix blur issues. #19883, @aocenas

  - Docker: Makes it possible to parse timezones in the
    docker image. #20081, @xlson

  - LDAP: All LDAP servers should be tried even if one of
    them returns a connection error. #20077, @jongyllen

  - LDAP: No longer shows incorrectly matching groups based
    on role in debug page. #20018, @xlson

  - Singlestat: Fix no data / null value mapping . #19951,
    @ryantxu

Revert the spec file and make script

Remove PhantomJS dependency

Update to 6.4.3

  - Bug Fixes

  - Alerting: All notification channels should send even if
    one fails to send. #19807, @jan25

  - AzureMonitor: Fix slate interference with dropdowns.
    #19799, @aocenas

  - ContextMenu: make ContextMenu positioning aware of the
    viewport width. #19699, @krvajal

  - DataLinks: Fix context menu not showing in
    singlestat-ish visualisations. #19809, @dprokop

  - DataLinks: Fix url field not releasing focus. #19804,
    @aocenas

  - Datasource: Fixes clicking outside of some query editors
    required 2 clicks. #19822, @aocenas

  - Panels: Fixes default tab for visualizations without
    Queries Tab. #19803, @hugohaggmark

  - Singlestat: Fixed issue with mapping null to text.
    #19689, @torkelo

  - @grafana/toolkit: Don't fail plugin creation when git
    user.name config is not set. #19821, @dprokop

  - @grafana/toolkit: TSLint line number off by 1. #19782,
    @fredwangwang

Update to 6.4.2

  - Bug Fixes

  - CloudWatch: Changes incorrect dimension wmlid to wlmid .
    #19679, @ATTron

  - Grafana Image Renderer: Fixes plugin page. #19664,
    @hugohaggmark

  - Graph: Fixes auto decimals logic for y axis ticks that
    results in too many decimals for high values. #19618,
    @torkelo

  - Graph: Switching to series mode should re-render graph.
    #19623, @torkelo

  - Loki: Fix autocomplete on label values. #19579, @aocenas

  - Loki: Removes live option for logs panel. #19533,
    @davkal

  - Profile: Fix issue with user profile not showing more
    than sessions sessions in some cases. #19578,
    @huynhsamha

  - Prometheus: Fixes so results in Panel always are sorted
    by query order. #19597, @hugohaggmark

  - sted keys in YAML provisioning caused a server crash,
    #19547

  - ImageRendering: Fixed issue with image rendering in
    enterprise build (Enterprise)

  - Reporting: Fixed issue with reporting service when STMP
    was disabled (Enterprise).

Changes from 6.4.0

  - Features / Enhancements

  - Build: Upgrade go to 1.12.10. #19499, @marefr

  - DataLinks: Suggestions menu improvements. #19396,
    @dprokop

  - Explore: Take root_url setting into account when
    redirecting from dashboard to explore. #19447,
    @ivanahuckova

  - Explore: Update broken link to logql docs. #19510,
    @ivanahuckova

  - Logs: Adds Logs Panel as a visualization. #19504,
    @davkal

  - Bug Fixes

  - CLI: Fix version selection for plugin install. #19498,
    @aocenas

  - Graph: Fixes minor issue with series override color
    picker and custom color . #19516, @torkelo

Changes from 6.4.0 Beta 2

  - Features / Enhancements

  - Azure Monitor: Remove support for cross resource queries
    (#19115)'. #19346, @sunker

  - Docker: Upgrade packages to resolve reported
    vulnerabilities. #19188, @marefr

  - Graphite: Time range expansion reduced from 1 minute to
    1 second. #19246, @torkelo

  - grafana/toolkit: Add plugin creation task. #19207,
    @dprokop

  - Bug Fixes

  - Alerting: Prevents creating alerts from unsupported
    queries. #19250, @hugohaggmark

  - Alerting: Truncate PagerDuty summary when greater than
    1024 characters. #18730, @nvllsvm

  - Cloudwatch: Fix autocomplete for Gamelift dimensions.
    #19146, @kevinpz

  - Dashboard: Fix export for sharing when panels use
    default data source. #19315, @torkelo

  - Database: Rewrite system statistics query to perform
    better. #19178, @papagian

  - Gauge/BarGauge: Fix issue with [object Object] in titles
    . #19217, @ryantxu

  - MSSQL: Revert usage of new connectionstring format
    introduced by #18384. #19203, @marefr

  - Multi-LDAP: Do not fail-fast on invalid credentials.
    #19261, @gotjosh

  - MySQL, Postgres, MSSQL: Fix validating query with
    template variables in alert . #19237, @marefr

  - MySQL, Postgres: Update raw sql when query builder
    updates. #19209, @marefr

  - MySQL: Limit datasource error details returned from the
    backend. #19373, @marefr

Changes from 6.4.0 Beta 1

  - Features / Enhancements

  - API: Readonly datasources should not be created via the
    API. #19006, @papagian

  - Alerting: Include configured AlertRuleTags in Webhooks
    notifier. #18233, @dominic-miglar

  - Annotations: Add annotations support to Loki. #18949,
    @aocenas

  - Annotations: Use a single row to represent a region.
    #17673, @ryantxu

  - Auth: Allow inviting existing users when login form is
    disabled. #19048, @548017

  - Azure Monitor: Add support for cross resource queries.
    #19115, @sunker

  - CLI: Allow installing custom binary plugins. #17551,
    @aocenas

  - Dashboard: Adds Logs Panel (alpha) as visualization
    option for Dashboards. #18641, @hugohaggmark

  - Dashboard: Reuse query results between panels . #16660,
    @ryantxu

  - Dashboard: Set time to to 23:59:59 when setting To time
    using calendar. #18595, @simPod

  - DataLinks: Add DataLinks support to Gauge, BarGauge and
    SingleStat2 panel. #18605, @ryantxu

  - DataLinks: Enable access to labels & field names.
    #18918, @torkelo

  - DataLinks: Enable multiple data links per panel. #18434,
    @dprokop

  - Docker: switch docker image to alpine base with
    phantomjs support. #18468, @DanCech

  - Elasticsearch: allow templating queries to order by
    doc_count. #18870, @hackery

  - Explore: Add throttling when doing live queries. #19085,
    @aocenas

  - Explore: Adds ability to go back to dashboard,
    optionally with query changes. #17982, @kaydelaney

  - Explore: Reduce default time range to last hour. #18212,
    @davkal

  - Gauge/BarGauge: Support decimals for min/max. #18368,
    @ryantxu

  - Graph: New series override transform constant that
    renders a single point as a line across the whole graph.
    #19102, @davkal

  - Image rendering: Add deprecation warning when PhantomJS
    is used for rendering images. #18933, @papagian

  - InfluxDB: Enable interpolation within ad-hoc filter
    values. #18077, @kvc-code

  - LDAP: Allow an user to be synchronized against LDAP.
    #18976, @gotjosh

  - Ldap: Add ldap debug page. #18759, @peterholmberg

  - Loki: Remove prefetching of default label values.
    #18213, @davkal

  - Metrics: Add failed alert notifications metric. #18089,
    @koorgoo

  - OAuth: Support JMES path lookup when retrieving user
    email. #14683, @bobmshannon

  - OAuth: return GitLab groups as a part of user info
    (enable team sync). #18388, @alexanderzobnin

  - Panels: Add unit for electrical charge - ampere-hour.
    #18950, @anirudh-ramesh

  - Plugin: AzureMonitor - Reapply MetricNamespace support.
    #17282, @raphaelquati

  - Plugins: better warning when plugins fail to load.
    #18671, @ryantxu

  - Postgres: Add support for scram sha 256 authentication.
    #18397, @nonamef

  - RemoteCache: Support SSL with Redis. #18511, @kylebrandt

  - SingleStat: The gauge option in now disabled/hidden
    (unless it's an old panel with it already enabled) .
    #18610, @ryantxu

  - Stackdriver: Add extra alignment period options. #18909,
    @sunker

  - Units: Add South African Rand (ZAR) to currencies.
    #18893, @jeteon

  - Units: Adding T,P,E,Z,and Y bytes. #18706, @chiqomar

  - Bug Fixes

  - Alerting: Notification is sent when state changes from
    no_data to ok. #18920, @papagian

  - Alerting: fix duplicate alert states when the alert
    fails to save to the database. #18216, @kylebrandt

  - Alerting: fix response popover prompt when add
    notification channels. #18967, @lzdw

  - CloudWatch: Fix alerting for queries with Id (using
    GetMetricData). #17899, @alex-berger

  - Explore: Fix auto completion on label values for Loki.
    #18988, @aocenas

  - Explore: Fixes crash using back button with a zoomed in
    graph. #19122, @hugohaggmark

  - Explore: Fixes so queries in Explore are only run if
    Graph/Table is shown. #19000, @hugohaggmark

  - MSSQL: Change connectionstring to URL format to fix
    using passwords with semicolon. #18384, @Russiancold

  - MSSQL: Fix memory leak when debug enabled. #19049,
    @briangann

  - Provisioning: Allow escaping literal '$' with '$$' in
    configs to avoid interpolation. #18045, @kylebrandt

  - TimePicker: Fixes hiding time picker dropdown in
    FireFox. #19154, @hugohaggmark

  - Breaking changes

  + Annotations There are some breaking changes in the
    annotations HTTP API for region annotations. Region
    annotations are now represented using a single event
    instead of two separate events. Check breaking changes
    in HTTP API below and HTTP API documentation for more
    details.

  + Docker Grafana is now using Alpine 3.10 as docker base
    image.

  + HTTP API

  - GET /api/alert-notifications now requires at least
    editor access.

New /api/alert-notifications/lookup returns less information than

/api/alert-notifications and can be access by any authenticated user.

  - GET /api/alert-notifiers now requires at least editor
    access

  - GET /api/org/users now requires org admin role. New

/api/org/users/lookup returns less information than /api/org/users and
can

be access by users that are org admins, admin in any folder or admin
of

any team.

  - GET /api/annotations no longer returns regionId
    property.

  - POST /api/annotations no longer supports isRegion
    property.

  - PUT /api/annotations/:id no longer supports isRegion
    property.

  - PATCH /api/annotations/:id no longer supports isRegion
    property.

  - DELETE /api/annotations/region/:id has been removed.

  - Deprecation notes

  + PhantomJS

  - PhantomJS, which is used for rendering images of
    dashboards and

panels, is deprecated and will be removed in a future Grafana release.
A

deprecation warning will from now on be logged when Grafana starts up
if

PhantomJS is in use. Please consider migrating from PhantomJS to the

Grafana Image Renderer plugin.

Changes from 6.3.6

  - Features / Enhancements

  - Metrics: Adds setting for turning off total stats
    metrics. #19142, @marefr

  - Bug Fixes

  - Database: Rewrite system statistics query to perform
    better. #19178, @papagian

  - Explore: Fixes error when switching from prometheus to
    loki data sources. #18599, @kaydelaney

Rebase package spec. Use mostly from fedora, fix suse specified things
and fix some errors.

Add missing directories provisioning/datasources and
provisioning/notifiers and sample.yaml as described in
packaging/rpm/control from upstream. Missing directories are shown in
logfiles.

Version 6.3.5

  - Upgrades

  + Build: Upgrade to go 1.12.9.

  - Bug Fixes

  + Dashboard: Fixes dashboards init failed loading error
    for dashboards with panel links that had missing
    properties.

  + Editor: Fixes issue where only entire lines were being
    copied.

  + Explore: Fixes query field layout in splitted view for
    Safari browsers.

  + LDAP: multildap + ldap integration.

  + Profile/UserAdmin: Fix for user agent parser crashes
    grafana-server on 32-bit builds.

  + Prometheus: Prevents panel editor crash when switching
    to Prometheus datasource.

  + Prometheus: Changes brace-insertion behavior to be less
    annoying.

Version 6.3.4

  - Security: CVE-2019-15043 - Parts of the HTTP API allow
    unauthenticated use.

Version 6.3.3

  - Bug Fixes

  + Annotations: Fix failing annotation query when time
    series query is cancelled. #18532 1, @dprokop 1

  + Auth: Do not set SameSite cookie attribute if
    cookie_samesite is none. #18462 1, @papagian 3

  + DataLinks: Apply scoped variables to data links
    correctly. #18454 1, @dprokop 1

  + DataLinks: Respect timezone when displaying
    datapoint&acirc;&#128;&#153;s timestamp in graph context
    menu. #18461 2, @dprokop 1

  + DataLinks: Use datapoint timestamp correctly when
    interpolating variables. #18459 1, @dprokop 1

  + Explore: Fix loading error for empty queries. #18488 1,
    @davkal

  + Graph: Fixes legend issue clicking on series line icon
    and issue with horizontal scrollbar being visible on
    windows. #18563 1, @torkelo 2

  + Graphite: Avoid glob of single-value array variables .
    #18420, @gotjosh

  + Prometheus: Fix queries with label_replace remove the $1
    match when loading query editor. #18480 5, @hugohaggmark
    3

  + Prometheus: More consistently allows for multi-line
    queries in editor. #18362 2, @kaydelaney 2

  + TimeSeries: Assume values are all numbers. #18540 4,
    @ryantxu

Version 6.3.2

  - Bug Fixes

  + Gauge/BarGauge: Fixes issue with losts thresholds and
    issue loading Gauge with avg stat. #18375 12

Version 6.3.1

  - Bug Fixes

  + PanelLinks: Fix crash issue Gauge & Bar Gauge for panels
    with panel links (drill down links). #18430 2

Version 6.3.0

  - Features / Enhancements

  + OAuth: Do not set SameSite OAuth cookie if
    cookie_samesite is None. #18392 4, @papagian 3

  + Auth Proxy: Include additional headers as part of the
    cache key. #18298 6, @gotjosh

  + Build grafana images consistently. #18224 12,
    @hassanfarid

  + Docs: SAML. #18069 11, @gotjosh

  + Permissions: Show plugins in nav for non admin users but
    hide plugin configuration. #18234 1, @aocenas

  + TimePicker: Increase max height of quick range dropdown.
    #18247 2, @torkelo 2

  + Alerting: Add tags to alert rules. #10989 13, @Thib17 1

  + Alerting: Attempt to send email notifications to all
    given email addresses. #16881 1, @zhulongcheng

  + Alerting: Improve alert rule testing. #16286 2, @marefr

  + Alerting: Support for configuring content field for
    Discord alert notifier. #17017 2, @jan25

  + Alertmanager: Replace illegal chars with underscore in
    label names. #17002 5, @bergquist 1

  + Auth: Allow expiration of API keys. #17678, @papagian 3

  + Auth: Return device, os and browser when listing user
    auth tokens in HTTP API. #17504, @shavonn 1

  + Auth: Support list and revoke of user auth tokens in UI.
    #17434 2, @shavonn 1

  + AzureMonitor: change clashing built-in Grafana
    variables/macro names for Azure Logs. #17140, @shavonn 1

  + CloudWatch: Made region visible for AWS Cloudwatch
    Expressions. #17243 2, @utkarshcmu

  + Cloudwatch: Add AWS DocDB metrics. #17241, @utkarshcmu

  + Dashboard: Use timezone dashboard setting when exporting
    to CSV. #18002 1, @dehrax

  + Data links. #17267 11, @torkelo 2

  + Docker: Switch base image to ubuntu:latest from
    debian:stretch to avoid security
    issues&acirc;&#128;&brvbar; #17066 5, @bergquist 1

  + Elasticsearch: Support for visualizing logs in Explore .
    #17605 7, @marefr

  + Explore: Adds Live option for supported datasources.
    #17062 1, @hugohaggmark 3

  + Explore: Adds orgId to URL for sharing purposes. #17895
    1, @kaydelaney 2

  + Explore: Adds support for new loki
    &acirc;&#128;&#152;start&acirc;&#128;&#153; and
    &acirc;&#128;&#152;end&acirc;&#128;&#153; params for
    labels endpoint. #17512, @kaydelaney 2

  + Explore: Adds support for toggling raw query mode in
    explore. #17870, @kaydelaney 2

  + Explore: Allow switching between metrics and logs .
    #16959 2, @marefr

  + Explore: Combines the timestamp and local time columns
    into one. #17775, @hugohaggmark 3

  + Explore: Display log lines context . #17097, @dprokop 1

  + Explore: Don&acirc;&#128;&#153;t parse log levels if
    provided by field or label. #17180 1, @marefr

  + Explore: Improves performance of Logs element by
    limiting re-rendering. #17685, @kaydelaney 2

  + Explore: Support for new LogQL filtering syntax. #16674
    4, @davkal

  + Explore: Use new TimePicker from Grafana/UI. #17793,
    @hugohaggmark 3

  + Explore: handle newlines in LogRow Highlighter. #17425,
    @rrfeng 1

  + Graph: Added new fill gradient option. #17528 3,
    @torkelo 2

  + GraphPanel: Don&acirc;&#128;&#153;t sort series when
    legend table & sort column is not visible . #17095,
    @shavonn 1

  + InfluxDB: Support for visualizing logs in Explore.
    #17450 9, @hugohaggmark 3

  + Logging: Login and Logout actions (#17760). #17883 1,
    @ATTron

  + Logging: Move log package to pkg/infra. #17023,
    @zhulongcheng

  + Metrics: Expose stats about roles as metrics. #17469 2,
    @bergquist 1

  + MySQL/Postgres/MSSQL: Add parsing for day, weeks and
    year intervals in macros. #13086 6, @bernardd

  + MySQL: Add support for periodically reloading client
    certs. #14892, @tpetr

  + Plugins: replace dataFormats list with skipDataQuery
    flag in plugin.json. #16984, @ryantxu

  + Prometheus: Take timezone into account for step
    alignment. #17477, @fxmiii

  + Prometheus: Use overridden panel range for $__range
    instead of dashboard range. #17352, @patrick246

  + Prometheus: added time range filter to series labels
    query. #16851 3, @FUSAKLA

  + Provisioning: Support folder that
    doesn&acirc;&#128;&#153;t exist yet in dashboard
    provisioning. #17407 1, @Nexucis

  + Refresh picker: Handle empty intervals. #17585 1,
    @dehrax

  + Singlestat: Add y min/max config to singlestat
    sparklines. #17527 4, @pitr

  + Snapshot: use given key and deleteKey. #16876,
    @zhulongcheng

  + Templating: Correctly display __text in multi-value
    variable after page reload. #17840 1, @EduardSergeev

  + Templating: Support selecting all filtered values of a
    multi-value variable. #16873 2, @r66ad

  + Tracing: allow propagation with Zipkin headers. #17009
    4, @jrockway

  + Users: Disable users removed from LDAP. #16820 2,
    @alexanderzobnin

  - Bug Fixes

  + PanelLinks: Fix render issue when there is no panel
    description. #18408 3, @dehrax

  + OAuth: Fix &acirc;&#128;&#156;missing saved
    state&acirc;&#128;&#157; OAuth login failure due to
    SameSite cookie policy. #18332 1, @papagian 3

  + cli: fix for recognizing when in dev
    mode&acirc;&#128;&brvbar; #18334, @xlson

  + DataLinks: Fixes incorrect interpolation of
    ${__series_name} . #18251 1, @torkelo 2

  + Loki: Display live tailed logs in correct order in
    Explore. #18031 3, @kaydelaney 2

  + PhantomJS: Fixes rendering on Debian Buster. #18162 2,
    @xlson

  + TimePicker: Fixed style issue for custom range popover.
    #18244, @torkelo 2

  + Timerange: Fixes a bug where custom time ranges
    didn&acirc;&#128;&#153;t respect UTC. #18248 1,
    @kaydelaney 2

  + remote_cache: Fix redis connstr parsing. #18204 1,
    @mblaschke

  + AddPanel: Fix issue when removing moved add panel widget
    . #17659 2, @dehrax

  + CLI: Fix encrypt-datasource-passwords fails with sql
    error. #18014, @marefr

  + Elasticsearch: Fix default max concurrent shard
    requests. #17770 4, @marefr

  + Explore: Fix browsing back to dashboard panel. #17061,
    @jschill

  + Explore: Fix filter by series level in logs graph.
    #17798, @marefr

  + Explore: Fix issues when loading and both graph/table
    are collapsed. #17113, @marefr

  + Explore: Fix selection/copy of log lines. #17121,
    @marefr

  + Fix: Wrap value of multi variable in array when coming
    from URL. #16992 1, @aocenas

  + Frontend: Fix for Json tree component not working.
    #17608, @srid12

  + Graphite: Fix for issue with alias function being moved
    last. #17791, @torkelo 2

  + Graphite: Fixes issue with seriesByTag & function with
    variable param. #17795, @torkelo 2

  + Graphite: use POST for /metrics/find requests. #17814 2,
    @papagian 3

  + HTTP Server: Serve Grafana with a custom URL path
    prefix. #17048 6, @jan25

  + InfluxDB: Fixes single quotes are not escaped in label
    value filters. #17398 1, @Panzki

  + Prometheus: Correctly escape
    &acirc;&#128;&#152;|&acirc;&#128;&#153; literals in
    interpolated PromQL variables. #16932, @Limess

  + Prometheus: Fix when adding label for metrics which
    contains colons in Explore. #16760, @tolwi

  + SinglestatPanel: Remove background color when value
    turns null. #17552 1, @druggieri

Make phantomjs dependency configurable

Create plugin directory and clean up (create in %install, add to
%files) handling of /var/lib/grafana/* and

mgr-cfg :

Remove commented code in test files

Replace spacewalk-usix with uyuni-common-libs

Bump version to 4.1.0 (bsc#1154940)

Add mgr manpage links

mgr-custom-info :

Bump version to 4.1.0 (bsc#1154940)

mgr-daemon :

Bump version to 4.1.0 (bsc#1154940)

Fix systemd timer configuration on SLE12 (bsc#1142038)

mgr-osad :

Separate osa-dispatcher and jabberd so it can be disabled
independently

Replace spacewalk-usix with uyuni-common-libs

Bump version to 4.1.0 (bsc#1154940)

Move /usr/share/rhn/config-defaults to uyuni-base-common

Require uyuni-base-common for /etc/rhn (for osa-dispatcher)

Ensure bytes type when using hashlib to avoid traceback (bsc#1138822)

mgr-push :

Replace spacewalk-usix and spacewalk-backend-libs with
uyuni-common-libs

Bump version to 4.1.0 (bsc#1154940)

mgr-virtualization :

Replace spacewalk-usix with uyuni-common-libs

Bump version to 4.1.0 (bsc#1154940)

Fix mgr-virtualization timer

rhnlib :

Fix building

Fix malformed XML response when data contains non-ASCII chars
(bsc#1154968)

Bump version to 4.1.0 (bsc#1154940)

Fix bootstrapping SLE11SP4 trad client with SSL enabled (bsc#1148177)

spacecmd :

Only report real error, not result (bsc#1171687)

Use defined return values for spacecmd methods so scripts can check
for failure (bsc#1171687)

Disable globbing for api subcommand to allow wildcards in filter
settings (bsc#1163871)

Bugfix: attempt to purge SSM when it is empty (bsc#1155372)

Bump version to 4.1.0 (bsc#1154940)

Prevent error when piping stdout in Python 2 (bsc#1153090)

Java api expects content as encoded string instead of encoded bytes
like before (bsc#1153277)

Enable building and installing for Ubuntu 16.04 and Ubuntu 18.04

Add unit test for schedule, errata, user, utils, misc, configchannel
and kickstart modules

Multiple minor bugfixes alongside the unit tests

Bugfix: referenced variable before assignment.

Add unit test for report, package, org, repo and group

spacewalk-client-tools :

Add workaround for uptime overflow to spacewalk-update-status as well
(bsc#1165921)

Spell correctly 'successful' and 'successfully'

Skip dmidecode data on aarch64 to prevent coredump (bsc#1113160)

Replace spacewalk-usix with uyuni-common-libs

Return a non-zero exit status on errors in rhn_check

Bump version to 4.1.0 (bsc#1154940)

Make a explicit requirement to systemd for spacewalk-client-tools when
rhnsd timer is installed

spacewalk-koan :

Bump version to 4.1.0 (bsc#1154940)

Require commands we use in merge-rd.sh

spacewalk-oscap :

Bump version to 4.1.0 (bsc#1154940)

spacewalk-remote-utils :

Update spacewalk-create-channel with RHEL 7.7 channel definitions

Bump version to 4.1.0 (bsc#1154940)

supportutils-plugin-susemanager-client :

Bump version to 4.1.0 (bsc#1154940)

suseRegisterInfo :

SuseRegisterInfo only needs perl-base, not full perl (bsc#1168310)

Bump version to 4.1.0 (bsc#1154940)

zypp-plugin-spacewalk :

Prevent issue with non-ASCII characters in Python 2 systems
(bsc#1172462)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1113160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1134195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1138822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1141661"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1142038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1143913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1148177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1153090"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1153277"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1154940"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1154968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1155372"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1163871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1165921"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1168310"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1170231"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1170557"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1171687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1172462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-10215/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-15043/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-12245/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-13379/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20201970-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?495a9824"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud Crowbar 9 :

zypper in -t patch SUSE-OpenStack-Cloud-Crowbar-9-2020-1970=1

SUSE OpenStack Cloud Crowbar 8 :

zypper in -t patch SUSE-OpenStack-Cloud-Crowbar-8-2020-1970=1

SUSE OpenStack Cloud 9 :

zypper in -t patch SUSE-OpenStack-Cloud-9-2020-1970=1

SUSE OpenStack Cloud 8 :

zypper in -t patch SUSE-OpenStack-Cloud-8-2020-1970=1

SUSE Manager Tools 12 :

zypper in -t patch SUSE-SLE-Manager-Tools-12-2020-1970=1

SUSE Linux Enterprise Server for SAP 12-SP4 :

zypper in -t patch SUSE-SLE-SAP-12-SP4-2020-1970=1

SUSE Linux Enterprise Server for SAP 12-SP3 :

zypper in -t patch SUSE-SLE-SAP-12-SP3-2020-1970=1

SUSE Linux Enterprise Server 12-SP5 :

zypper in -t patch SUSE-SLE-SERVER-12-SP5-2020-1970=1

SUSE Linux Enterprise Server 12-SP4-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP4-LTSS-2020-1970=1

SUSE Linux Enterprise Server 12-SP3-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP3-2020-1970=1

SUSE Linux Enterprise Server 12-SP3-BCL :

zypper in -t patch SUSE-SLE-SERVER-12-SP3-BCL-2020-1970=1

SUSE Enterprise Storage 5 :

zypper in -t patch SUSE-Storage-5-2020-1970=1

HPE Helion Openstack 8 :

zypper in -t patch HPE-Helion-OpenStack-8-2020-1970=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:golang-github-prometheus-node_exporter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(3|4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP3/4/5", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"golang-github-prometheus-node_exporter-0.18.1-1.6.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"golang-github-prometheus-node_exporter-0.18.1-1.6.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"golang-github-prometheus-node_exporter-0.18.1-1.6.2")) flag++;


if (flag)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
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
