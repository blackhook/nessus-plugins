#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1914-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(128618);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2019-10181", "CVE-2019-10182", "CVE-2019-10185");

  script_name(english:"Debian DLA-1914-1 : icedtea-web security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security vulnerabilities were found in icedtea-web, an
implementation of the Java Network Launching Protocol (JNLP).

CVE-2019-10181

It was found that in icedtea-web executable code could be injected in
a JAR file without compromising the signature verification. An
attacker could use this flaw to inject code in a trusted JAR. The code
would be executed inside the sandbox.

CVE-2019-10182

It was found that icedtea-web did not properly sanitize paths from
<jar/> elements in JNLP files. An attacker could trick a victim into
running a specially crafted application and use this flaw to upload
arbitrary files to arbitrary locations in the context of the user.

CVE-2019-10185

It was found that icedtea-web was vulnerable to a zip-slip attack
during auto-extraction of a JAR file. An attacker could use this flaw
to write files to arbitrary locations. This could also be used to
replace the main running application and, possibly, break out of the
sandbox.

For Debian 8 'Jessie', these problems have been fixed in version
1.5.3-1+deb8u1.

We recommend that you upgrade your icedtea-web packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/09/msg00008.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/icedtea-web"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10181");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedtea-7-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedtea-netx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedtea-netx-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedtea-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"icedtea-7-plugin", reference:"1.5.3-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"icedtea-netx", reference:"1.5.3-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"icedtea-netx-common", reference:"1.5.3-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"icedtea-plugin", reference:"1.5.3-1+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
