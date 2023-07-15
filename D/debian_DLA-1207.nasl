#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1207-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105325);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-1000385");

  script_name(english:"Debian DLA-1207-1 : erlang security update (ROBOT)");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An erlang TLS server configured with cipher suites using RSA key
exchange, may be vulnerable to an Adaptive Chosen Ciphertext attack
(AKA Bleichenbacher attack) against RSA, which when exploited, may
result in plaintext recovery of encrypted messages and/or a
Man-in-the-middle (MiTM) attack, despite the attacker not having
gained access to the server's private key itself.

For Debian 7 'Wheezy', these problems have been fixed in version
15.b.1-dfsg-4+deb7u2.

We recommend that you upgrade your erlang packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/12/msg00010.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/erlang"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-appmon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-asn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-base-hipe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-common-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-corba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-dialyzer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-diameter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-edoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-eldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-erl-docgen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-eunit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-gs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-ic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-ic-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-inets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-inviso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-jinterface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-manpages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-megaco");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-mnesia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-mode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-observer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-os-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-parsetools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-percept");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-pman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-public-key");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-reltool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-runtime-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-syntax-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-test-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-toolbar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-tv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-typer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-webtool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-wx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-xmerl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/15");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"erlang", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-appmon", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-asn1", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-base", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-base-hipe", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-common-test", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-corba", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-crypto", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-debugger", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-dev", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-dialyzer", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-diameter", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-doc", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-edoc", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-eldap", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-erl-docgen", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-et", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-eunit", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-examples", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-gs", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-ic", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-ic-java", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-inets", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-inviso", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-jinterface", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-manpages", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-megaco", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-mnesia", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-mode", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-nox", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-observer", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-odbc", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-os-mon", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-parsetools", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-percept", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-pman", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-public-key", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-reltool", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-runtime-tools", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-snmp", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-src", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-ssh", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-ssl", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-syntax-tools", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-test-server", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-toolbar", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-tools", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-tv", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-typer", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-webtool", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-wx", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-x11", reference:"15.b.1-dfsg-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"erlang-xmerl", reference:"15.b.1-dfsg-4+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
