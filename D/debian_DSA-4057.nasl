#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4057. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105089);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-1000385");
  script_xref(name:"DSA", value:"4057");

  script_name(english:"Debian DSA-4057-1 : erlang - security update (ROBOT)");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the TLS server in Erlang is vulnerable to an
adaptive chosen ciphertext attack against RSA keys."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/erlang"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/erlang"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/erlang"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-4057"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the erlang packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 1:17.3-dfsg-4+deb8u2.

For the stable distribution (stretch), this problem has been fixed in
version 1:19.2.1+dfsg-2+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/08");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/08");
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
if (deb_check(release:"8.0", prefix:"erlang", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-asn1", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-base", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-base-hipe", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-common-test", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-corba", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-crypto", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-dbg", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-debugger", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-dev", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-dialyzer", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-diameter", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-doc", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-edoc", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-eldap", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-erl-docgen", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-et", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-eunit", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-examples", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-gs", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-ic", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-ic-java", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-inets", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-jinterface", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-manpages", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-megaco", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-mnesia", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-mode", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-nox", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-observer", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-odbc", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-os-mon", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-parsetools", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-percept", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-public-key", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-reltool", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-runtime-tools", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-snmp", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-src", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-ssh", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-ssl", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-syntax-tools", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-test-server", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-tools", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-typer", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-webtool", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-wx", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-x11", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"erlang-xmerl", reference:"1:17.3-dfsg-4+deb8u2")) flag++;
if (deb_check(release:"9.0", prefix:"erlang", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-asn1", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-base", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-base-hipe", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-common-test", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-corba", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-crypto", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-dbg", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-debugger", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-dev", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-dialyzer", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-diameter", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-doc", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-edoc", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-eldap", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-erl-docgen", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-et", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-eunit", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-examples", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-gs", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-ic", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-ic-java", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-inets", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-jinterface", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-manpages", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-megaco", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-mnesia", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-mode", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-nox", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-observer", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-odbc", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-os-mon", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-parsetools", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-percept", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-public-key", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-reltool", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-runtime-tools", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-snmp", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-src", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-ssh", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-ssl", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-syntax-tools", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-tools", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-typer", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-wx", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-x11", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"erlang-xmerl", reference:"1:19.2.1+dfsg-2+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
