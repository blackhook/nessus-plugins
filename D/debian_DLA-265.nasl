#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-265-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(84507);
  script_version("2.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-3206");
  script_bugtraq_id(74760);

  script_name(english:"Debian DLA-265-2 : pykerberos regression update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the original fix did not disable KDC
verification support by default and changed checkPassowrd()'s
signature. This update corrects this.

This was the text of the original advisiory :

Martin Prpic has reported the possibility of a man-in-the-middle
attack in the pykerberos code to the Red Hat Bugzilla (Fedora bug
tracker). The original issue has earlier been reported upstream [1].
We are quoting the upstream bug reported partially below :

The python-kerberos checkPassword() method has been badly insecure in
previous releases. It used to do (and still does by default) a kinit
(AS-REQ) to ask a KDC for a TGT for the given user principal, and
interprets the success or failure of that as indicating whether the
password is correct. It does not, however, verify that it actually
spoke to a trusted KDC: an attacker may simply reply instead with an
AS-REP which matches the password he just gave you.

Imagine you were verifying a password using LDAP authentication rather
than Kerberos: you would, of course, use TLS in conjunction with LDAP
to make sure you were talking to a real, trusted LDAP server. The same
requirement applies here. kinit is not a password-verification
service.

The usual way of doing this is to take the TGT you've obtained with
the user's password, and then obtain a ticket for a principal for
which the verifier has keys (e.g. a web server processing a
username/password form login might get a ticket for its own
HTTP/host@REALM principal), which it can then verify. Note that this
requires that the verifier has its own Kerberos identity, which is
mandated by the symmetric nature of Kerberos (whereas in the LDAP
case, the use of public-key cryptography allows anonymous
verification).

With this version of the pykerberos package a new option is introduced
for the checkPassword() method. Setting verify to True when using
checkPassword() will perform a KDC verification. For this to work, you
need to provide a krb5.keytab file containing service principal keys
for the service you intend to use.

As the default krb5.keytab file in /etc is normally not accessible by
non-root users/processes, you have to make sure a custom krb5.keytab
file containing the correct principal keys is provided to your
application using the KRB5_KTNAME environment variable.

Note: In Debian squeeze(-lts), KDC verification support is disabled by
default in order not to break existing setups.

[1] https://www.calendarserver.org/ticket/833

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/08/msg00015.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/pykerberos"
  );
  # https://www.calendarserver.org/ticket/833
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/apple/ccs-pykerberos/issues/31"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected python-kerberos package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-kerberos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"6.0", prefix:"python-kerberos", reference:"1.1+svn4895-1+deb6u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
