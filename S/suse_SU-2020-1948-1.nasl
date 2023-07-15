#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:1948-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(138760);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2020-10700", "CVE-2020-10704", "CVE-2020-10730", "CVE-2020-10745", "CVE-2020-10760", "CVE-2020-14303");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : ldb, samba (SUSE-SU-2020:1948-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for ldb, samba fixes the following issues :

Changes in samba: Update to samba 4.11.11

  + CVE-2020-10730: NULL de-reference in AD DC LDAP server
    when ASQ and VLV combined; (bso#14364); (bsc#1173159]

  + CVE-2020-10745: invalid DNS or NBT queries containing
    dots use several seconds of CPU each; (bso#14378);
    (bsc#1173160).

  + CVE-2020-10760: Use-after-free in AD DC Global Catalog
    LDAP server with paged_result or VLV; (bso#14402);
    (bsc#1173161)

  + CVE-2020-14303: Endless loop from empty UDP packet sent
    to AD DC nbt_server; (bso#14417); (bsc#1173359).

Update to samba 4.11.10

  + Fix segfault when using SMBC_opendir_ctx() routine for
    share folder that contains incorrect symbols in any file
    name; (bso#14374).

  + vfs_shadow_copy2 doesn't fail case looking in
    snapdirseverywhere mode; (bso#14350)

  + ldb_ldap: Fix off-by-one increment in lldb_add_msg_attr;
    (bso#14413).

  + Malicous SMB1 server can crash libsmbclient; (bso#14366)

  + winbindd: Fix a use-after-free when winbind clients
    exit; (bso#14382)

  + ldb: Bump version to 2.0.11, LMDB databases can grow
    without bounds. (bso#14330)

Update to samba 4.11.9

  + nmblib: Avoid undefined behaviour in handle_name_ptrs();
    (bso#14242).

  + 'samba-tool group' commands do not handle group names
    with special chars correctly; (bso#14296).

  + smbd: avoid calling vfs_file_id_from_sbuf() if statinfo
    is not valid; (bso#14237).

  + Missing check for DMAPI offline status in async DOS
    attributes; (bso#14293).

  + smbd: Ignore set NTACL requests which contain S-1-5-88
    NFS ACEs; (bso#14307).

  + vfs_recycle: Prevent flooding the log if we're called on
    non-existant paths; (bso#14316)

  + smbd mistakenly updates a file's write-time on close;
    (bso#14320).

  + RPC handles cannot be differentiated in source3 RPC
    server; (bso#14359).

  + librpc: Fix IDL for svcctl_ChangeServiceConfigW;
    (bso#14313).

  + nsswitch: Fix use-after-free causing segfault in
    _pam_delete_cred; (bso#14327).

  + Fix fruit:time machine max size on arm; (bso#13622)

  + CTDB recovery corner cases can cause record resurrection
    and node banning; (bso#14294).

  + ctdb: Fix a memleak; (bso#14348).

  + libsmb: Don't try to find posix stat info in
    SMBC_getatr().

  + ctdb-tcp: Move free of inbound queue to TCP restart;
    (bso#14295); (bsc#1162680).

  + s3/librpc/crypto: Fix double free with unresolved
    credential cache; (bso#14344); (bsc#1169095)

  + s3:libads: Fix ads_get_upn(); (bso#14336).

  + CTDB recovery corner cases can cause record resurrection
    and node banning; (bso#14294)

  + Starting ctdb node that was powered off hard before
    results in recovery loop; (bso#14295); (bsc#1162680).

  + ctdb-recoverd: Avoid dereferencing NULL rec->nodemap;
    (bso#14324)

Update to samba 4.11.8

  + CVE-2020-10700: Use-after-free in Samba AD DC LDAP
    Server with ASQ; (bso#14331); (bsc#1169850);

  + CVE-2020-10704: LDAP Denial of Service (stack overflow)
    in Samba AD DC; (bso#14334); (bsc#1169851);

Update to samba 4.11.7

  + s3: lib: nmblib. Clean up and harden nmb packet
    processing; (bso#14239).

  + s3: VFS: full_audit. Use system session_info if called
    from a temporary share definition; (bso#14283)

  + dsdb: Correctly handle memory in objectclass_attrs;
    (bso#14258).

  + ldb: version 2.0.9, Samba 4.11 and later give incorrect
    results for SCOPE_ONE searches; (bso#14270)

  + auth: Fix CIDs 1458418 and 1458420 NULL pointer
    dereferences; (bso#14247).

  + smbd: Handle EINTR from open(2) properly; (bso#14285)

  + winbind member (source3) fails local SAM auth with empty
    domain name; (bso#14247)

  + winbindd: Handling missing idmap in getgrgid();
    (bso#14265).

  + lib:util: Log mkdir error on correct debug levels;
    (bso#14253).

  + wafsamba: Do not use 'rU' as the 'U' is deprecated in
    Python 3.9; (bso#14266).

  + ctdb-tcp: Make error handling for outbound connection
    consistent; (bso#14274).

Update to samba 4.11.6

  + pygpo: Use correct method flags; (bso#14209).

  + vfs_ceph_snapshots: Fix root relative path handling;
    (bso#14216); (bsc#1141320).

  + Avoiding bad call flags with python 3.8, using
    METH_NOARGS instead of zero; (bso#14209).

  + source4/utils/oLschema2ldif: Include stdint.h before
    cmocka.h; (bso#14218).

  + docs-xml/winbindnssinfo: Clarify interaction with
    idmap_ad etc; (bso#14122).

  + smbd: Fix the build with clang; (bso#14251).

  + upgradedns: Ensure lmdb lock files linked; (bso#14199).

  + s3: VFS: glusterfs: Reset nlinks for symlink entries
    during readdir; (bso#14182).

  + smbc_stat() doesn't return the correct st_mode and also
    the uid/gid is not filled (SMBv1) file; (bso#14101).

  + librpc: Fix string length checking in
    ndr_pull_charset_to_null(); (bso#14219).

  + ctdb-scripts: Strip square brackets when gathering
    connection info; (bso#14227).

Add libnetapi-devel to baselibs conf, for wine usage; (bsc#1172307);

Installing: samba - samba-ad-dc.service does not exist and unit not
found; (bsc#1171437);

Fix samba_winbind package is installing python3-base without python3
package; (bsc#1169521);

Changes in ldb: Update to version 2.0.12

  + CVE-2020-10730: NULL de-reference in AD DC LDAP server
    when ASQ and VLV combined; (bso#14364); (bsc#1173159).

  + ldb_ldap: fix off-by-one increment in lldb_add_msg_attr;
    (bso#14413).

  + lib/ldb: add unit test for ldb_ldap internal code.

Update to version 2.0.11

  + lib ldb: lmdb init var before calling mdb_reader_check.

  + lib ldb: lmdb clear stale readers on write txn start;
    (bso#14330).

  + ldb tests: Confirm lmdb free list handling

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1141320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1162680"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1169095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1169521"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1169850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1169851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1171437"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1172307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1173159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1173160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1173161"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1173359"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1174120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-10700/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-10704/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-10730/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-10745/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-10760/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-14303/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20201948-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?35b12723"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Python2 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Python2-15-SP2-2020-1948=1

SUSE Linux Enterprise Module for Basesystem 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP2-2020-1948=1

SUSE Linux Enterprise High Availability 15-SP2 :

zypper in -t patch SUSE-SLE-Product-HA-15-SP2-2020-1948=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ldb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ldb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ldb-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-samr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-samr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-samr0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libldb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libldb2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libldb2-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libldb2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-errors-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-errors0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-errors0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-errors0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-policy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-policy-python3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-policy0-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-policy0-python3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap2-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-ldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-ldb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-ldb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-ad-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-ad-dc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-ceph-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-dsdb-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-dsdb-modules-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs-python3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-python3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/20");
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
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP2", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libdcerpc-binding0-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libdcerpc-binding0-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libdcerpc0-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libdcerpc0-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libldb2-32bit-2.0.12-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libldb2-32bit-debuginfo-2.0.12-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libndr-krb5pac0-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libndr-krb5pac0-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libndr-nbt0-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libndr-nbt0-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libndr-standard0-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libndr-standard0-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libndr0-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libndr0-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libnetapi0-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libnetapi0-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libsamba-credentials0-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libsamba-credentials0-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libsamba-errors0-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libsamba-errors0-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libsamba-hostconfig0-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libsamba-hostconfig0-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libsamba-passdb0-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libsamba-passdb0-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libsamba-util0-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libsamba-util0-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libsamdb0-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libsamdb0-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libsmbconf0-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libsmbconf0-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libsmbldap2-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libsmbldap2-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libtevent-util0-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libtevent-util0-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libwbclient0-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libwbclient0-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"samba-ceph-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"samba-ceph-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"samba-libs-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"samba-libs-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"samba-winbind-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"samba-winbind-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"ldb-debugsource-2.0.12-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"ldb-tools-2.0.12-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"ldb-tools-debuginfo-2.0.12-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libdcerpc-binding0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libdcerpc-binding0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libdcerpc-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libdcerpc-samr-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libdcerpc-samr0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libdcerpc-samr0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libdcerpc0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libdcerpc0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libldb-devel-2.0.12-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libldb2-2.0.12-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libldb2-debuginfo-2.0.12-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libndr-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libndr-krb5pac-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libndr-krb5pac0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libndr-krb5pac0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libndr-nbt-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libndr-nbt0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libndr-nbt0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libndr-standard-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libndr-standard0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libndr-standard0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libndr0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libndr0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libnetapi-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libnetapi0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libnetapi0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-credentials-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-credentials0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-credentials0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-errors-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-errors0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-errors0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-hostconfig-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-hostconfig0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-hostconfig0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-passdb-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-passdb0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-passdb0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-policy-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-policy-python3-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-policy0-python3-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-policy0-python3-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-util-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-util0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamba-util0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamdb-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamdb0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsamdb0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsmbclient-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsmbclient0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsmbclient0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsmbconf-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsmbconf0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsmbconf0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsmbldap-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsmbldap2-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libsmbldap2-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libtevent-util-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libtevent-util0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libtevent-util0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libwbclient-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libwbclient0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libwbclient0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python3-ldb-2.0.12-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python3-ldb-debuginfo-2.0.12-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python3-ldb-devel-2.0.12-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-ad-dc-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-ad-dc-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-client-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-client-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-core-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-debugsource-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-dsdb-modules-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-dsdb-modules-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-libs-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-libs-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-libs-python3-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-libs-python3-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-python3-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-python3-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-winbind-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"samba-winbind-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libdcerpc-binding0-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libdcerpc-binding0-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libdcerpc0-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libdcerpc0-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libldb2-32bit-2.0.12-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libldb2-32bit-debuginfo-2.0.12-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libndr-krb5pac0-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libndr-krb5pac0-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libndr-nbt0-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libndr-nbt0-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libndr-standard0-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libndr-standard0-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libndr0-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libndr0-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libnetapi0-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libnetapi0-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libsamba-credentials0-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libsamba-credentials0-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libsamba-errors0-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libsamba-errors0-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libsamba-hostconfig0-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libsamba-hostconfig0-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libsamba-passdb0-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libsamba-passdb0-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libsamba-util0-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libsamba-util0-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libsamdb0-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libsamdb0-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libsmbconf0-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libsmbconf0-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libsmbldap2-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libsmbldap2-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libtevent-util0-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libtevent-util0-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libwbclient0-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libwbclient0-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"samba-ceph-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"samba-ceph-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"samba-libs-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"samba-libs-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"samba-winbind-32bit-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"samba-winbind-32bit-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"ldb-debugsource-2.0.12-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"ldb-tools-2.0.12-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"ldb-tools-debuginfo-2.0.12-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libdcerpc-binding0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libdcerpc-binding0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libdcerpc-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libdcerpc-samr-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libdcerpc-samr0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libdcerpc-samr0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libdcerpc0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libdcerpc0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libldb-devel-2.0.12-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libldb2-2.0.12-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libldb2-debuginfo-2.0.12-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libndr-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libndr-krb5pac-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libndr-krb5pac0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libndr-krb5pac0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libndr-nbt-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libndr-nbt0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libndr-nbt0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libndr-standard-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libndr-standard0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libndr-standard0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libndr0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libndr0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libnetapi-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libnetapi0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libnetapi0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-credentials-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-credentials0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-credentials0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-errors-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-errors0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-errors0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-hostconfig-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-hostconfig0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-hostconfig0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-passdb-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-passdb0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-passdb0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-policy-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-policy-python3-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-policy0-python3-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-policy0-python3-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-util-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-util0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamba-util0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamdb-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamdb0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsamdb0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsmbclient-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsmbclient0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsmbclient0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsmbconf-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsmbconf0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsmbconf0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsmbldap-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsmbldap2-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libsmbldap2-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libtevent-util-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libtevent-util0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libtevent-util0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libwbclient-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libwbclient0-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libwbclient0-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python3-ldb-2.0.12-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python3-ldb-debuginfo-2.0.12-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python3-ldb-devel-2.0.12-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-ad-dc-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-ad-dc-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-client-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-client-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-core-devel-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-debugsource-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-dsdb-modules-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-dsdb-modules-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-libs-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-libs-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-libs-python3-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-libs-python3-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-python3-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-python3-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-winbind-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"samba-winbind-debuginfo-4.11.11+git.180.2cf3b203f07-4.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ldb / samba");
}
