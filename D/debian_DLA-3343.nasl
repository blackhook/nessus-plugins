#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3343. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(171917);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/03");

  script_cve_id("CVE-2023-26314");

  script_name(english:"Debian DLA-3343-1 : mono - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by a vulnerability as referenced in the dla-3343
advisory.

  - The mono package before 6.8.0.105+dfsg-3.3 for Debian allows arbitrary code execution because the
    application/x-ms-dos-executable MIME type is associated with an un-sandboxed Mono CLR interpreter.
    (CVE-2023-26314)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=972146");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/mono");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3343");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-26314");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/mono");
  script_set_attribute(attribute:"solution", value:
"Upgrade the mono packages.

For Debian 10 buster, this problem has been fixed in version 5.18.0.240+dfsg-3+deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-26314");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ca-certificates-mono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-2.0-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-2.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-accessibility4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-btls-interface4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-cairo4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-cecil-private-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-cil-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-codecontracts4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-compilerservices-symbolwriter4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-corlib4.5-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-cscompmgd0.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-csharp4.0c-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-custommarshalers4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-data-tds4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-db2-1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-debugger-soft4.0a-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-http4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-i18n-cjk4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-i18n-mideast4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-i18n-other4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-i18n-rare4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-i18n-west4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-i18n4.0-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-i18n4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-ldap4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-management4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-messaging-rabbitmq4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-messaging4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-microsoft-build-engine4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-microsoft-build-framework4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-microsoft-build-tasks-v4.0-4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-microsoft-build-utilities-v4.0-4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-microsoft-build4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-microsoft-csharp4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-microsoft-visualc10.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-microsoft-web-infrastructure1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-oracle4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-parallel4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-peapi4.0a-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-posix4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-profiler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-rabbitmq4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-relaxng4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-security4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-sharpzip4.84-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-simd4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-smdiagnostics0.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-sqlite4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-componentmodel-composition4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-componentmodel-dataannotations4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-configuration-install4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-configuration4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-core4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-data-datasetextensions4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-data-entity4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-data-linq4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-data-services-client4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-data-services4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-data4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-deployment4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-design4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-drawing-design4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-drawing4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-dynamic4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-enterpriseservices4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-identitymodel-selectors4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-identitymodel4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-io-compression-filesystem4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-io-compression4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-json-microsoft4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-json4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-ldap-protocols4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-ldap4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-management4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-messaging4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-net-http-formatting4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-net-http-webrequest4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-net-http4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-net4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-numerics-vectors4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-numerics4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-reactive-core2.2-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-reactive-debugger2.2-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-reactive-experimental2.2-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-reactive-interfaces2.2-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-reactive-linq2.2-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-reactive-observable-aliases0.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-reactive-platformservices2.2-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-reactive-providers2.2-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-reactive-runtime-remoting2.2-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-reactive-windows-forms2.2-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-reactive-windows-threading2.2-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-reflection-context4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-runtime-caching4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-runtime-durableinstancing4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-runtime-serialization-formatters-soap4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-runtime-serialization4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-runtime4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-security4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-servicemodel-activation4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-servicemodel-discovery4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-servicemodel-internals0.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-servicemodel-routing4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-servicemodel-web4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-servicemodel4.0a-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-serviceprocess4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-threading-tasks-dataflow4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-transactions4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-web-abstractions4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-web-applicationservices4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-web-dynamicdata4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-web-extensions-design4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-web-extensions4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-web-http-selfhost4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-web-http-webhost4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-web-http4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-web-mobile4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-web-mvc3.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-web-razor2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-web-regularexpressions4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-web-routing4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-web-services4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-web-webpages-deployment2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-web-webpages-razor2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-web-webpages2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-web4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-windows-forms-datavisualization4.0a-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-windows-forms4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-windows4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-workflow-activities4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-workflow-componentmodel4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-workflow-runtime4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-xaml4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-xml-linq4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-xml-serialization4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-xml4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-tasklets4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-webbrowser4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-webmatrix-data4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-windowsbase4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-xbuild-tasks4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmonoboehm-2.0-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmonoboehm-2.0-1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmonoboehm-2.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmonosgen-2.0-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmonosgen-2.0-1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmonosgen-2.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-4.0-gac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-4.0-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-complete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-csharp-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-gac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-jay");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-mcs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-runtime-boehm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-runtime-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-runtime-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-runtime-sgen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-xbuild");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:monodoc-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:monodoc-manual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'ca-certificates-mono', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-2.0-1', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-2.0-dev', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-accessibility4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-btls-interface4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-cairo4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-cecil-private-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-cil-dev', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-codecontracts4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-compilerservices-symbolwriter4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-corlib4.5-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-cscompmgd0.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-csharp4.0c-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-custommarshalers4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-data-tds4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-db2-1.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-debugger-soft4.0a-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-http4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-i18n-cjk4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-i18n-mideast4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-i18n-other4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-i18n-rare4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-i18n-west4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-i18n4.0-all', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-i18n4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-ldap4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-management4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-messaging-rabbitmq4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-messaging4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-microsoft-build-engine4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-microsoft-build-framework4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-microsoft-build-tasks-v4.0-4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-microsoft-build-utilities-v4.0-4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-microsoft-build4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-microsoft-csharp4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-microsoft-visualc10.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-microsoft-web-infrastructure1.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-oracle4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-parallel4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-peapi4.0a-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-posix4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-profiler', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-rabbitmq4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-relaxng4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-security4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-sharpzip4.84-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-simd4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-smdiagnostics0.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-sqlite4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-componentmodel-composition4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-componentmodel-dataannotations4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-configuration-install4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-configuration4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-core4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-data-datasetextensions4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-data-entity4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-data-linq4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-data-services-client4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-data-services4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-data4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-deployment4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-design4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-drawing-design4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-drawing4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-dynamic4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-enterpriseservices4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-identitymodel-selectors4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-identitymodel4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-io-compression-filesystem4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-io-compression4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-json-microsoft4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-json4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-ldap-protocols4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-ldap4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-management4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-messaging4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-net-http-formatting4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-net-http-webrequest4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-net-http4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-net4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-numerics-vectors4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-numerics4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-reactive-core2.2-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-reactive-debugger2.2-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-reactive-experimental2.2-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-reactive-interfaces2.2-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-reactive-linq2.2-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-reactive-observable-aliases0.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-reactive-platformservices2.2-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-reactive-providers2.2-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-reactive-runtime-remoting2.2-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-reactive-windows-forms2.2-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-reactive-windows-threading2.2-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-reflection-context4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-runtime-caching4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-runtime-durableinstancing4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-runtime-serialization-formatters-soap4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-runtime-serialization4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-runtime4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-security4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-servicemodel-activation4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-servicemodel-discovery4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-servicemodel-internals0.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-servicemodel-routing4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-servicemodel-web4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-servicemodel4.0a-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-serviceprocess4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-threading-tasks-dataflow4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-transactions4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-web-abstractions4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-web-applicationservices4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-web-dynamicdata4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-web-extensions-design4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-web-extensions4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-web-http-selfhost4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-web-http-webhost4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-web-http4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-web-mobile4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-web-mvc3.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-web-razor2.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-web-regularexpressions4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-web-routing4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-web-services4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-web-webpages-deployment2.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-web-webpages-razor2.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-web-webpages2.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-web4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-windows-forms-datavisualization4.0a-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-windows-forms4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-windows4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-workflow-activities4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-workflow-componentmodel4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-workflow-runtime4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-xaml4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-xml-linq4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-xml-serialization4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system-xml4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-system4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-tasklets4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-webbrowser4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-webmatrix-data4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-windowsbase4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmono-xbuild-tasks4.0-cil', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmonoboehm-2.0-1', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmonoboehm-2.0-1-dbg', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmonoboehm-2.0-dev', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmonosgen-2.0-1', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmonosgen-2.0-1-dbg', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libmonosgen-2.0-dev', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'mono-4.0-gac', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'mono-4.0-service', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'mono-complete', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'mono-csharp-shell', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'mono-dbg', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'mono-devel', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'mono-gac', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'mono-jay', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'mono-mcs', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'mono-runtime', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'mono-runtime-boehm', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'mono-runtime-common', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'mono-runtime-dbg', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'mono-runtime-sgen', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'mono-source', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'mono-utils', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'mono-xbuild', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'monodoc-base', 'reference': '5.18.0.240+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'monodoc-manual', 'reference': '5.18.0.240+dfsg-3+deb10u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ca-certificates-mono / libmono-2.0-1 / libmono-2.0-dev / etc');
}
