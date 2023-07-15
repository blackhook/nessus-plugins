#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-46.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(145357);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/27");

  script_cve_id("CVE-2011-4953", "CVE-2012-2395", "CVE-2017-1000469", "CVE-2018-1000225", "CVE-2018-1000226", "CVE-2018-10931");

  script_name(english:"openSUSE Security Update : cobbler (openSUSE-2021-46)");
  script_summary(english:"Check for the openSUSE-2021-46 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for cobbler fixes the following issues :

  - Add cobbler-tests subpackage for unit testing for
    openSUSE/SLE 

  - Adds LoadModule definitions for openSUSE/SLE

  - Switch to new refactored auth module.

  - use systemctl to restart cobblerd on logfile rotation
    (boo#1169207) Mainline logrotate conf file uses already
    /sbin/service instead of outdated: /etc/init.d/cobblerd

  - Fix cobbler sync for DHCP or DNS (boo#1169553) Fixed
    mainline by commit 2d6cfe42da

  - Signatures file now uses 'default_autoinstall' which
    fixes import problem happening with some distributions
    (boo#1159010)

  - Fix for kernel and initrd detection (boo#1159010)

  - New :

  - For the distro there is now a parameter
    remote_boot_initrd and remote_boot_kernel ()

  - For the profile there is now a parameter filename for
    DHCP. (#2280)

  - Signatures for ESXi 6 and 7 (#2308)

  - The hardlink command is now detected more dynamically
    and thus more error resistant (#2297)

  - HTTPBoot will now work in some cases out of the bug.
    (#2295)

  - Additional DNS query for a case where the wrong record
    was queried in the nsupdate system case (#2285)

  - Changes :

  - Enabled a lot of tests, removed some and implemented
    new. (#2202)

  - Removed not used files from the codebase. (#2302)

  - Exchanged mkisofs to xorrisofs. (#2296)

  - Removed duplicate code. (#2224)

  - Removed unreachable code. (#2223)

  - Snippet creation and deletion now works again via
    xmlrpc. (#2244)

  - Replace createrepo with createrepo_c. (#2266)

  - Enable Kerberos through having a case sensitive
    users.conf. (#2272)

  - Bugfixes :

  - General various Bugfixes (#2331, )

  - Makefile usage and commands. (#2344, #2304)

  - Fix the dhcp template. (#2314)

  - Creation of the management classes and gPXE. (#2310)

  - Fix the scm_track module. (#2275, #2279)

  - Fix passing the netdevice parameter correctly to the
    linuxrc. (#2263)

  - powerstatus from cobbler now works thanks to a wrapper
    for ipmitool. (#2267)

  - In case the LDAP is used for auth, it now works with
    ADs. (#2274)

  - Fix passthru authentication. (#2271)

  - Other :

  - Add Codecov. (#2229)

  - Documentation updates. (#2333, #2326, #2305, #2249,
    #2268)

  - Buildprocess :

  - Recreation and cleanup of Grub2. (#2278)

  - Fix small errors for openSUSE Leap. (#2233)

  - Fix rpmlint errors. (#2237)

  - Maximum compatibility for debbuild package creation.
    (#2255, #2292, #2242, #2300)

  - Fixes related to our CI Pipeline (#2254, #2269)

  - Internal Code cleanup (#2273, #2270)

  - Breaking Changes :

  - Hash handling in users.digest file. (#2299) 

  - Updated to version 3.1.1.

  - Introduce new packaging from upstream

  - Changelog see below

  - New :

  - We are now having a cross-distro specfile which can be
    build in the OBS (#2220) - before rewritten it was
    improved by #2144 & #2174

  - Grub Submenu for net-booting machines (#2217)

  - Building the Cent-OS RPMs in Docker (#2190 #2189)

  - Reintroduced manpage build in setup.py (#2185)

  - mgmt_parameters are now passed to the dhcp template
    (#2182)

  - Using the standard Pyhton3 logger instead of a custom
    one (#2160 #2139 #2151)

  - Script for converting the settings file from 3.0.0 to
    3.0.1 (#2154)

  - Docs now inside the repo instead of cobbler.github.io
    and improved with sphinx (#2117)

  - Changes :

  - The default tftpboot directory is now /var/lib/tftpboot
    instead of previously /srv/tftpboot (#2220)

  - Distro signatures were adjusted where necessary (#2219
    #2134)

  - Removed requirements.txt and placed the requirements in
    setup.py (#2204)

  - Display only entries in grub which are from the same
    arch (#2191 #2216)

  - Change the name of the cobbler manpage form cobbler-cli
    to cobbler back and move it to section 8 (#2188 #2186)

  - Bugfixes :

  - Incremented Version to 3.1.1 from 3.0.1

  - S390 Support was cleaned up (#2207 #2178)

  - PowerPC Support was cleaned up (#2178)

  - Added a missing import while importing a distro with
    cobbler import (#2201)

  - Fixed a case where a stacktrace would be produced so
    pass none instead (#2203)

  - Rename of suse_kopts_textmode_overwrite to
    kops_overwrite to utils (#2143 #2200)

  - Fix rsync subprocess call (#2199 #2179)

  - Fixed an error where the template rendering did not work
    (#2176)

  - Fixed some cobbler import errors (#2172)

  - Wrong shebang in various scripts (#2148)

  - Fix some imports which fixes errors introduced by the
    remodularization (#2150 #2153)

  - Other :

  - Issue Templates for Github (#2187)

  - Update to latest git HEAD code base This version (from
    mainline so for quite a while already) also includes
    fixes for 'boo#1149075' and boo#1151875

  - Fix for cobbler import and buildiso (boo#1156574)

  - Adjusted manpage creation (needs sphinx as
    BuildRequires)

  - Fix cobbler sync for dhcp and dns enabled due to latest
    module renaming patches

  - Update to latest git HEAD

  - Fixes permission denied in apache2 context when trying
    to write cobbler log

  - Fixes a bad import in import_signature (item)

  - Fixes bad shebang bash path in mkgrub.sh (used in post
    section)

  - Now track Github master branch WARNING: This release
    contains breaking changes for your settings file! 

  - Notable changes :

  - Now using standard python logger

  - Updated dhcpd.template 

  - Removed fix_shebang.patch: now in upstream. 

  - added -s parameter to fdupes call to prevent hardlink
    across partititons

  - Update to latest v3.0.0 cobbler release

  - Add previouly added patch:
    exclude_get-loaders_command.patch to the list of patches
    to apply.

  - Fix log file world readable (as suggested by Matthias
    Gerstner) and change file attributes via attr in spec
    file

  - Do not allow get-loaders command (download of
    third-party provided network boot loaders we do not
    trust)

  - Mainline fixes: 3172d1df9b9cc8 Add missing help text in
    redhat_management_key field c8f5490e507a72 Set default
    interface if cobbler system add has no

    --interface= param 31a1aa31d26c4a Remove apache
    IfVersion tags from apache configs

  - Integrated fixes that came in from mainline from other
    products (to calm down obs regression checker):
    CVE-2011-4953, fate#312397, boo#660126, boo#671212,
    boo#672471, boo#682665 boo#687891, boo#695955,
    boo#722443, boo#722445, boo#757062, boo#763610
    boo#783671, boo#790545, boo#796773, boo#811025,
    boo#812948, boo#842699 boo#846580, boo#869371,
    boo#884051, boo#976826, boo#984998 Some older bugs need
    boo# references as well: boo#660126, boo#671212,
    boo#672471, boo#682665 boo#687891, boo#695955,
    boo#722443, boo#722445, boo#757062, boo#763610
    boo#783671, boo#790545, boo#796773, boo#811025,
    boo#812948, boo#842699 boo#846580, boo#869371,
    boo#884051

  - Fix for redhat_management_key not being listed as a
    choice during profile rename (boo#1134588)

  - Added :

  - rhn-mngmnt-key-field-fix.diff

  - Fixes distribution detection in setup.py for SLESo

  - Added :

  -
    changes-detection-to-distro-like-for-suse-distributions.
    diff

  - Moving to pytest and adding Docker test integration

  - Added :

  - add-docker-integration-testing.diff

  - refactor-unittest-to-pytest.diff

  - Additional compatability changes for old Koan versions.

  - Modified :

  - renamed-methods-alias-part2.patch

  - Old Koan versions not only need method aliases, but also
    need compatible responses

  - Added :

  - renamed-methods-alias-part2.patch

  - Add the redhat_managment_* fields again to enable
    templating in SUMA.

  - Added :

  - revert-redhat-management-removal.patch 

  - Changes return of last_modified_time RPC to float

  - Added :

  - changes-return-to-float.diff

  - provide old name aliases for all renamed methods :

  - get_distro_for_koan => get_distro_as_rendered

  - get_profile_for_koan => get_profile_as_rendered

  - get_system_for_koan => get_system_as_rendered

  - get_repo_for_koan => get_repo_as_rendered

  - get_image_for_koan => get_image_as_rendered

  - get_mgmtclass_for_koan => get_mgmtclass_as_rendered

  - get_package_for_koan => get_package_as_rendered

  - get_file_for_koan => get_file_as_rendered

  - Renamed: get_system_for_koan.patch =>
    renamed-methods-alias.patch

  - provide renamed method 'get_system_for_koan' under old
    name for old clients.

  - Added :

  - get_system_for_koan.patch

  - Bring back power_system method in the XML-RPC API

  - Changed lanplus option to lanplus=true in
    fence_ipmitool.template

  - Added :

  - power_system_xmlrpc_api.patch

  - Changed :

  - fence_ipmitool.template

  - Disables nsupdate_enabled by default

  - Added :

  - disable_nsupdate_enabled_by_default.diff

  - Fixes issue in distribution detection with 'lower'
    function call.

  - Modified :

  - remodeled-distro-detection.diff 

  - Adds imporoved distribution detection. Since now all
    base products get detected correctly, we no longer need
    the SUSE Manager patch.

  - Added :

  - remodeled-distro-detection.diff 

  - fix grub directory layout

  - Added :

  - create-system-directory-at-the-correct-place.patch

  - fix HTTP status code of XMLRPC service

  - Added :

  - fix-http-status-code.patch

  - touch /etc/genders when it not exists (boo#1128926)

  - Add patches to fix logging

  - Added :

  - return-the-name-of-the-unknown-method.patch

  - call-with-logger-where-possible.patch

  - Switching version schema from 3.0 to 3.0.0

  - Fixes case where distribution detection returns None
    (boo#1130658)

  - Added :

  - fixes-distro-none-case.diff

  - Removes newline from token, which caused authentication
    error (boo#1128754)

  - Added :

  - remove-newline-from-token.diff

  - Added a patch which fixes an exception when login in
    with a non-root user.

  - Added :

  - fix-login-error.patch

  - Added a patch which fixes an exception when login in
    with a non-root user.

  - Added :

  - fix-login-error.patch



  - Remove patch merged at upstream :

  - 0001-return-token-as-string.patch

  - change grub2-x86_64-efi dependency to Recommends

  - grub2-i386pc is not really required. Changed to
    recommended to allow building for architectures other
    than x86_64

  - Use cdrtools starting with SLE-15 and Leap-15 again.
    (boo#1081739)

  - Update cobbler loaders server hostname (boo#980577)

  - Update outdated apache config (boo#956264)

  - Replace builddate with changelog date to fix
    build-compare (boo#969538)

  - LOCKFILE usage removed on openSUSE (boo#714618)

  - Power management subsystem completely re-worked to
    prevent command-injection (CVE-2012-2395)

  - Removed patch merged at upstream :

  - cobblerd_needs_apache2_service_started.patch

  - Checking bug fixes of released products are in latest
    develop pkg :

  - remove fix-nameserver-search.fix; bug is invalid
    (boo#1029276)

    -> not needed anymore

  - fix cobbler yaboot handling (boo#968406, boo#966622)

    -> no yaboot support anymore

  - support UEFI boot with cobbler generated tftp tree
    (boo#1020376)

    -> upstream

  - Enabling PXE grub2 support for PowerPC (boo#986978)

    -> We have grub2 support for ppc64le

  - (boo#1048183) fix missing args and location for xen

    -> is in

  - no koan support anymore: boo#969541, boo#924118,
    boo#967523

  - not installed (boo#966841) works.

  - These still have to be looked at: SUSE system as systemd
    only (boo#952844) handle list value for kernel options
    correctly (boo#973413) entry in pxe menu (boo#988889)

  - This still has to be switched off (at least in internal
    cobbler versions): Disabling 'get-loaders' command and
    'check' fixed. boo#973418

  - Add explicity require to tftp, so it is used for both
    SLE and openSUSE (originally from jgonzalez@suse.com)

  - Moved Recommends according to spec_cleaner

  - Require latest apache2-mod_wsgi-python3 package This
    fixes interface to http://localhost/cblr/svc/...

  - Use latest github cobbler/cobbler master branch in
    _service file

  - cobblerd_needs_apache2_service_started.patch reverted,
    that is mainline now :

  - Only recommend grub2-arm and grub2-ppc packages or we
    might not be able to build on factory where arm/ppc
    might not be built

  - Remove genders package requires. A genders file is
    generated, but we do not need/use the genders package.

  - Update to latest cobbler version 3.0 mainline git HEAD
    version and remove already integrated or not needed
    anymore patches.

  - Serial console support added, did some testing already
    Things should start to work as expected

  - Add general grub2 support

  - Put mkgrub.* into mkgrub.sh

  - Add git date and commit to version string for now

  - Add grub2 mkimage scripts: mkgrub.i386-pc
    mkgrub.powerpc-ieee1275 mkgrub.x86_64-efi
    mkgrub.arm64-efi and generate grub executables with them
    in the %post section



  - build server wants explicite package in BuildRequires;
    use tftp

  - require tftp(server) instead of atftp

  - cleanup: cobbler is noarch, so arch specific requires do
    not make sense

  - SLES15 is using /etc/os-release instead of
    /etc/SuSE-release, use this one for checking also

  - add sles15 distro profile (boo#1090205)

  - fix signature for SLES15 (boo#1075014)

  - fix signature for SLES15 (boo#1075014)

  - fix koan wait parameter initialization

  - Fix koan shebang

  - Escape shell parameters provided by the user for the
    reposync action (CVE-2017-1000469) (boo#1074594)

  - detect if there is already another instance of 'cobbler
    sync' running and exit with failure if so (boo#1081714)

  - do not try to hardlink to a symlink. The result will be
    a dangling symlink in the general case (boo#1097733)

  - fix service restart after logrotate for cobblerd
    (boo#1113747)

  - rotate cobbler logs at higher frequency to prevent disk
    fillup (boo#1113747)

  - Forbid exposure of private methods in the API
    (CVE-2018-10931) (CVE-2018-1000225) (boo#1104287)
    (boo#1104189) (boo#1105442)

  - Check access token when calling 'modify_setting' API
    endpoint (boo#1104190) (boo#1105440) (CVE-2018-1000226)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://localhost/cblr/svc/..."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020376"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1029276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074594"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081714"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097733"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104287"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105442"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113747"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1128754"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1128926"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151875"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156574"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169207"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169553"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=660126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=671212"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=672471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=682665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=687891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=695955"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=714618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=722443"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=722445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=757062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=763610"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=783671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=790545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=796773"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=811025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=812948"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=842699"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=846580"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=869371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=884051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=924118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=952844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=956264"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966622"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969538"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969541"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=973413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=973418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=976826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=980577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=988889"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/312397"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected cobbler packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cobbler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cobbler-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cobbler-web");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

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



flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"cobbler-3.1.2-lp152.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"cobbler-tests-3.1.2-lp152.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"cobbler-web-3.1.2-lp152.6.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cobbler / cobbler-tests / cobbler-web");
}
