#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1564-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118597);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2009-0689");
  script_bugtraq_id(35510, 36565, 36851, 37078, 37080, 37687, 37688);

  script_name(english:"Debian DLA-1564-1 : mono security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that Mono&rsquo;s string-to-double parser may crash, on
specially crafted input. This could lead to arbitrary code execution.

CVE-2018-1002208: Mono embeds the sharplibzip library which is
vulnerable to directory traversal, allowing attackers to write to
arbitrary files via a ../ (dot dot slash) in a Zip archive entry that
is mishandled during extraction. This vulnerability is also known as
'Zip-Slip'.

The Mono developers intend to entirely remove sharplibzip from the
sources and do not plan to fix this issue. It is therefore recommended
to fetch the latest sharplibzip version by using the nuget package
manager instead. The embedded version should not be used with
untrusted zip files.

For Debian 8 'Jessie', this problem has been fixed in version
3.2.8+dfsg-10+deb8u1.

We recommend that you upgrade your mono packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/11/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/mono"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-2.0-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-2.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-accessibility2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-accessibility4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-c5-1.1-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-cairo2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-cairo4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-cecil-private-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-cil-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-codecontracts4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-compilerservices-symbolwriter4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-corlib2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-corlib4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-corlib4.5-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-cscompmgd8.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-csharp4.0c-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-custommarshalers4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-data-tds2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-data-tds4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-db2-1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-debugger-soft2.0a-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-debugger-soft4.0a-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-entityframework-sqlserver6.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-entityframework6.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-http4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-i18n-cjk4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-i18n-mideast4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-i18n-other4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-i18n-rare4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-i18n-west2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-i18n-west4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-i18n2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-i18n4.0-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-i18n4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-ldap2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-ldap4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-management2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-management4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-messaging-rabbitmq2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-messaging-rabbitmq4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-messaging2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-messaging4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-microsoft-build-engine4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-microsoft-build-framework4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-microsoft-build-tasks-v4.0-4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-microsoft-build-utilities-v4.0-4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-microsoft-build2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-microsoft-build4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-microsoft-csharp4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-microsoft-visualc10.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-microsoft-web-infrastructure1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-microsoft8.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-npgsql2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-npgsql4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-opensystem-c4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-oracle2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-oracle4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-parallel4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-peapi2.0a-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-peapi4.0a-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-posix2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-posix4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-profiler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-rabbitmq2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-rabbitmq4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-relaxng2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-relaxng4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-security2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-security4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-sharpzip2.6-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-sharpzip2.84-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-sharpzip4.84-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-simd2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-simd4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-sqlite2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-sqlite4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-componentmodel-composition4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-componentmodel-dataannotations4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-configuration-install4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-configuration4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-core4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-data-datasetextensions4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-data-linq2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-data-linq4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-data-services-client4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-data-services2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-data-services4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-data2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-data4.0-cil");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-json2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-json4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-ldap-protocols4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-ldap2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-ldap4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-management4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-messaging2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-messaging4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-net-http-formatting4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-net-http-webrequest4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-net-http4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-net2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-net4.0-cil");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-runtime-caching4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-runtime-durableinstancing4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-runtime-serialization-formatters-soap4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-runtime-serialization4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-runtime2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-runtime4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-security4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-servicemodel-activation4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-servicemodel-discovery4.0-cil");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-web-mvc1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-web-mvc2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-web-mvc3.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-web-razor2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-web-routing4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-web-services4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-web-webpages-deployment2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-web-webpages-razor2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-web-webpages2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-web2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-web4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-windows-forms-datavisualization4.0a-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-windows-forms4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-windows4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-xaml4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-xml-linq4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-xml-serialization4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-xml4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-tasklets2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-tasklets4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-wcf3.0a-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-web4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-webbrowser2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-webbrowser4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-webmatrix-data4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-windowsbase3.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-windowsbase4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-winforms2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-xbuild-tasks2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-xbuild-tasks4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmonoboehm-2.0-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmonoboehm-2.0-1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmonoboehm-2.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmonosgen-2.0-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmonosgen-2.0-1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmonosgen-2.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-2.0-gac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-2.0-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-4.0-gac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-4.0-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-complete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-csharp-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-dmcs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-gac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-gmcs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-jay");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-mcs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-runtime-boehm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-runtime-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-runtime-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-runtime-sgen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-xbuild");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:monodoc-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:monodoc-manual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"8.0", prefix:"libmono-2.0-1", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-2.0-dev", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-accessibility2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-accessibility4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-c5-1.1-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-cairo2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-cairo4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-cecil-private-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-cil-dev", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-codecontracts4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-compilerservices-symbolwriter4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-corlib2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-corlib4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-corlib4.5-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-cscompmgd8.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-csharp4.0c-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-custommarshalers4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-data-tds2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-data-tds4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-db2-1.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-debugger-soft2.0a-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-debugger-soft4.0a-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-entityframework-sqlserver6.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-entityframework6.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-http4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-i18n-cjk4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-i18n-mideast4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-i18n-other4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-i18n-rare4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-i18n-west2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-i18n-west4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-i18n2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-i18n4.0-all", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-i18n4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-ldap2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-ldap4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-management2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-management4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-messaging-rabbitmq2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-messaging-rabbitmq4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-messaging2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-messaging4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-microsoft-build-engine4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-microsoft-build-framework4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-microsoft-build-tasks-v4.0-4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-microsoft-build-utilities-v4.0-4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-microsoft-build2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-microsoft-build4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-microsoft-csharp4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-microsoft-visualc10.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-microsoft-web-infrastructure1.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-microsoft8.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-npgsql2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-npgsql4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-opensystem-c4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-oracle2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-oracle4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-parallel4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-peapi2.0a-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-peapi4.0a-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-posix2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-posix4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-profiler", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-rabbitmq2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-rabbitmq4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-relaxng2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-relaxng4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-security2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-security4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-sharpzip2.6-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-sharpzip2.84-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-sharpzip4.84-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-simd2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-simd4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-sqlite2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-sqlite4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-componentmodel-composition4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-componentmodel-dataannotations4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-configuration-install4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-configuration4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-core4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-data-datasetextensions4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-data-linq2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-data-linq4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-data-services-client4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-data-services2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-data-services4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-data2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-data4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-design4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-drawing-design4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-drawing4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-dynamic4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-enterpriseservices4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-identitymodel-selectors4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-identitymodel4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-io-compression-filesystem4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-io-compression4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-json-microsoft4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-json2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-json4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-ldap-protocols4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-ldap2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-ldap4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-management4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-messaging2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-messaging4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-net-http-formatting4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-net-http-webrequest4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-net-http4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-net2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-net4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-numerics4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-reactive-core2.2-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-reactive-debugger2.2-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-reactive-experimental2.2-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-reactive-interfaces2.2-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-reactive-linq2.2-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-reactive-observable-aliases0.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-reactive-platformservices2.2-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-reactive-providers2.2-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-reactive-runtime-remoting2.2-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-reactive-windows-forms2.2-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-reactive-windows-threading2.2-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-runtime-caching4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-runtime-durableinstancing4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-runtime-serialization-formatters-soap4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-runtime-serialization4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-runtime2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-runtime4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-security4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-servicemodel-activation4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-servicemodel-discovery4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-servicemodel-routing4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-servicemodel-web4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-servicemodel4.0a-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-serviceprocess4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-threading-tasks-dataflow4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-transactions4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-web-abstractions4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-web-applicationservices4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-web-dynamicdata4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-web-extensions-design4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-web-extensions4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-web-http-selfhost4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-web-http-webhost4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-web-http4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-web-mvc1.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-web-mvc2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-web-mvc3.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-web-razor2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-web-routing4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-web-services4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-web-webpages-deployment2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-web-webpages-razor2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-web-webpages2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-web2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-web4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-windows-forms-datavisualization4.0a-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-windows-forms4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-windows4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-xaml4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-xml-linq4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-xml-serialization4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system-xml4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-system4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-tasklets2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-tasklets4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-wcf3.0a-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-web4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-webbrowser2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-webbrowser4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-webmatrix-data4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-windowsbase3.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-windowsbase4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-winforms2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-xbuild-tasks2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono-xbuild-tasks4.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmono2.0-cil", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmonoboehm-2.0-1", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmonoboehm-2.0-1-dbg", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmonoboehm-2.0-dev", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmonosgen-2.0-1", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmonosgen-2.0-1-dbg", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmonosgen-2.0-dev", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mono-2.0-gac", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mono-2.0-service", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mono-4.0-gac", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mono-4.0-service", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mono-complete", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mono-csharp-shell", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mono-dbg", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mono-devel", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mono-dmcs", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mono-gac", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mono-gmcs", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mono-jay", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mono-mcs", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mono-runtime", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mono-runtime-boehm", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mono-runtime-common", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mono-runtime-dbg", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mono-runtime-sgen", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mono-utils", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mono-xbuild", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"monodoc-base", reference:"3.2.8+dfsg-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"monodoc-manual", reference:"3.2.8+dfsg-10+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
