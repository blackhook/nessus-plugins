#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-892.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(138710);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/13");

  script_cve_id("CVE-2019-15043", "CVE-2020-12245", "CVE-2020-13379");

  script_name(english:"openSUSE Security Update : grafana / grafana-piechart-panel / grafana-status-panel (openSUSE-2020-892)");
  script_summary(english:"Check for the openSUSE-2020-892 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for grafana, grafana-piechart-panel, grafana-status-panel
fixes the following issues :

grafana was updated to version 7.0.3 :

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
    not removed but will be in a future release. We hope to
    address the underlying requirement of dynamic dashboards
    in a different way. #24059

  - The unofficial first version of backend plugins together
    with usage of grafana/grafana-plugin-model is now
    deprecated and support for that will be removed in a
    future release. Please refer to backend plugins
    documentation for information about the new officially
    supported backend plugins.

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

This update was imported from the SUSE:SLE-15-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170557"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected grafana / grafana-piechart-panel / grafana-status-panel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grafana");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grafana-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grafana-piechart-panel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grafana-status-panel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"grafana-7.0.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"grafana-debuginfo-7.0.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"grafana-piechart-panel-1.4.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"grafana-status-panel-1.0.9-lp152.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "grafana-piechart-panel / grafana-status-panel / grafana / etc");
}
