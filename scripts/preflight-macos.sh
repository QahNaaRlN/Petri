#!/bin/sh
# Read-only host/artifact inventory. This never launches or qualifies a sandbox.
set -u

profile=''
expected_version=''
expected_build=''
expected_arch=''
binary=''
helper=''
host='unknown'
actual_version=''
actual_build=''
actual_arch=''
standard_user='unverified'
developer_tools='not_queried'
codesign_tool='not_queried'
sandbox_exec_tool='not_queried'
binary_signature='not_provided'
binary_verification='not_run'
binary_sha256=''
helper_signature='not_provided'
helper_verification='not_run'
helper_sha256=''
status='UNVERIFIED'
reason='No runtime or isolation check was performed.'

json_string() {
    # Add one record delimiter so awk preserves any trailing newlines in input.
    printf '%s\n' "$1" | /usr/bin/awk '
        BEGIN {
            printf "\""
            for (i = 1; i < 32; i++) control[sprintf("%c", i)] = i
        }
        {
            if (NR > 1) printf "\\n"
            for (i = 1; i <= length($0); i++) {
                c = substr($0, i, 1)
                if (c == "\\") printf "\\\\"
                else if (c == "\"") printf "\\\""
                else if (c in control) printf "\\u%04x", control[c]
                else printf "%s", c
            }
        }
        END { printf "\"" }
    '
}

emit() {
    printf '{"schema":"petri.macos-preflight/v1","inventory_status":'
    json_string "$status"
    printf ',"reason":'; json_string "$reason"
    printf ',"profile":{"id":'; json_string "$profile"
    printf ',"authority":"caller-selected candidate, not accepted by this script","expected_version":'
    json_string "$expected_version"
    printf ',"expected_build":'; json_string "$expected_build"
    printf ',"expected_arch":'; json_string "$expected_arch"
    printf '},"host":{"system":'; json_string "$host"
    printf ',"product_version":'; json_string "$actual_version"
    printf ',"build":'; json_string "$actual_build"
    printf ',"architecture":'; json_string "$actual_arch"
    printf ',"standard_nonadmin_user":'; json_string "$standard_user"
    printf '},"tools":{"developer_tools":'; json_string "$developer_tools"
    printf ',"codesign":'; json_string "$codesign_tool"
    printf ',"sandbox_exec":'; json_string "$sandbox_exec_tool"
    printf ',"sdk_version":"NOT_QUERIED","compiler_execution":"NOT_RUN"},"artifacts":{"petri":{"path":'
    json_string "$binary"
    printf ',"signature_kind":'; json_string "$binary_signature"
    printf ',"signature_verification":'; json_string "$binary_verification"
    printf ',"sha256":'; json_string "$binary_sha256"
    printf '},"helper":{"path":'; json_string "$helper"
    printf ',"signature_kind":'; json_string "$helper_signature"
    printf ',"signature_verification":'; json_string "$helper_verification"
    printf ',"sha256":'; json_string "$helper_sha256"
    printf '}},"runtime_probe":"NOT_RUN","isolation_verified":false,"runtime_status":"UNVERIFIED","descendant_stop":"UNVERIFIED","aggregate_resources":"UNVERIFIED","notarization":"NOT_ASSESSED","release_acceptance":"UNVERIFIED"}\n'
}

invalid() {
    status='INVALID_REQUEST'
    reason="$1"
    emit
    exit 1
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --profile|--expected-version|--expected-build|--expected-arch|--petri-binary|--helper)
            [ "$#" -ge 2 ] || invalid "Missing value for $1"
            case "$1" in
                --profile) profile=$2 ;;
                --expected-version) expected_version=$2 ;;
                --expected-build) expected_build=$2 ;;
                --expected-arch) expected_arch=$2 ;;
                --petri-binary) binary=$2 ;;
                --helper) helper=$2 ;;
            esac
            shift 2
            ;;
        --help)
            printf '%s\n' 'Read-only macOS preflight; never starts or certifies a sandbox.' \
                'sh scripts/preflight-macos.sh --profile CANDIDATE_ID --expected-version EXACT --expected-build EXACT --expected-arch arm64 [--petri-binary EXPLICIT_FILE] [--helper EXPLICIT_FILE]' \
                'Without a complete caller-selected host pin, inventory exits 2 (UNVERIFIED).' \
                'Exit 0 means only that the requested inventory completed; isolation/release remain UNVERIFIED.'
            exit 0
            ;;
        *) invalid "Unknown argument: $1" ;;
    esac
done

case "$profile" in *[!a-zA-Z0-9._/-]*) invalid 'Profile ID contains unsupported characters.' ;; esac
case "$expected_version" in *[!0-9.]*) invalid 'Expected product version must contain only digits and periods.' ;; esac
case "$expected_build" in *[!a-zA-Z0-9]*) invalid 'Expected build must be an exact alphanumeric build identifier.' ;; esac
case "$expected_arch" in ''|arm64|x86_64) ;; *) invalid 'Expected architecture must be arm64 or x86_64.' ;; esac
case "$binary" in *[[:cntrl:]]*) invalid 'Artifact paths with control characters are unsupported.' ;; esac
case "$helper" in *[[:cntrl:]]*) invalid 'Artifact paths with control characters are unsupported.' ;; esac

host=$(/usr/bin/uname -s 2>/dev/null) || host='unknown'
if [ "$host" != 'Darwin' ]; then
    status='UNSUPPORTED_HOST'
    reason='This is not macOS. Native macOS isolation was not executed or verified.'
    emit
    exit 2
fi

actual_version=$(/usr/bin/sw_vers -productVersion 2>/dev/null) || actual_version=''
actual_build=$(/usr/bin/sw_vers -buildVersion 2>/dev/null) || actual_build=''
actual_arch=$(/usr/bin/uname -m 2>/dev/null) || actual_arch=''
if [ -z "$actual_version" ] || [ -z "$actual_build" ] || [ -z "$actual_arch" ]; then
    status='HOST_FACTS_UNVERIFIED'
    reason='Required OS product/build/architecture facts could not be read.'
    emit
    exit 2
fi
if [ -z "$profile" ] || [ -z "$expected_version" ] || [ -z "$expected_build" ] || [ -z "$expected_arch" ]; then
    status='PROFILE_NOT_PINNED'
    reason='Choose and record an explicit candidate profile, exact macOS version/build and architecture before a design probe. This script does not choose or accept them.'
    emit
    exit 2
fi
if [ "$actual_version" != "$expected_version" ] || [ "$actual_build" != "$expected_build" ] || [ "$actual_arch" != "$expected_arch" ]; then
    status='HOST_PROFILE_MISMATCH'
    reason='Observed OS version/build/architecture differs from the explicitly requested candidate. No fallback or compatibility claim was made.'
    emit
    exit 2
fi

uid=$(/usr/bin/id -u 2>/dev/null) || uid='unknown'
groups=$(/usr/bin/id -Gn 2>/dev/null) || groups='unknown'
case " $groups " in
    *' admin '*|*' unknown '*) standard_user='false' ;;
    *) if [ "$uid" = '0' ] || [ "$uid" = 'unknown' ]; then standard_user='false'; else standard_user='true'; fi ;;
esac
if [ "$standard_user" != 'true' ]; then
    status='ACCOUNT_UNSUITABLE'
    reason='Use a dedicated standard non-admin account; do not use sudo, change group membership or elevate to satisfy this preflight.'
    emit
    exit 2
fi

# Presence only. Running xcrun/clang shims can trigger developer-tool setup on
# an unprepared host, so this inventory does not invoke them or request install.
if [ -x /usr/bin/xcrun ] && [ -x /usr/bin/xcode-select ]; then
    developer_tools='PRESENT_NOT_EXECUTED_SDK_UNVERIFIED'
else
    developer_tools='NOT_PRESENT'
fi
if [ -x /usr/bin/codesign ]; then codesign_tool='PRESENT'; else codesign_tool='NOT_PRESENT'; fi
if [ -x /usr/bin/sandbox-exec ]; then sandbox_exec_tool='PRESENT_NOT_EXECUTED_NOT_SELECTED'; else sandbox_exec_tool='NOT_PRESENT_NOT_SELECTED'; fi

inspect_artifact() {
    inspected_signature='not_provided'
    inspected_verification='not_run'
    inspected_sha256=''
    [ -n "$1" ] || return 0
    case "$1" in
        /*) ;;
        *) inspected_signature='UNVERIFIED_ABSOLUTE_CODE_PATH_REQUIRED'; return 1 ;;
    esac
    if [ ! -f "$1" ] || [ -L "$1" ]; then
        inspected_signature='UNVERIFIED_NOT_REGULAR_OR_SYMLINK'
        inspected_verification='NOT_RUN'
        return 1
    fi
    if [ ! -x /usr/bin/codesign ] || [ ! -x /usr/bin/shasum ]; then
        inspected_signature='UNVERIFIED_TOOLS_UNAVAILABLE'
        return 1
    fi
    # Explicit code-artifact arguments only: no home, keychain, identity or
    # credential enumeration, no signing, execution, Gatekeeper or network call.
    metadata=$(/usr/bin/codesign --display --verbose=2 "$1" 2>&1)
    if [ "$?" -eq 0 ]; then
        case "$metadata" in
            *'Signature=adhoc'*) inspected_signature='ad_hoc' ;;
            *'Authority=Developer ID Application:'*) inspected_signature='developer_id' ;;
            *) inspected_signature='signed_other' ;;
        esac
        if /usr/bin/codesign --verify --strict "$1" >/dev/null 2>&1; then
            inspected_verification='VALID_STATIC_SIGNATURE'
        else
            inspected_verification='INVALID_STATIC_SIGNATURE'
        fi
    else
        inspected_signature='UNSIGNED_OR_UNREADABLE'
        inspected_verification='UNVERIFIED'
    fi
    # Hash stdin so filename escaping cannot prefix the digest with a backslash.
    hash_line=$(/usr/bin/shasum -a 256 < "$1" 2>/dev/null) || return 1
    inspected_sha256=${hash_line%% *}
    [ "${#inspected_sha256}" -eq 64 ] || return 1
    case "$inspected_sha256" in *[!0-9a-f]*) return 1 ;; esac
    return 0
}

if inspect_artifact "$binary"; then binary_inspected='true'; else binary_inspected='false'; fi
binary_signature=$inspected_signature
binary_verification=$inspected_verification
binary_sha256=$inspected_sha256
if inspect_artifact "$helper"; then helper_inspected='true'; else helper_inspected='false'; fi
helper_signature=$inspected_signature
helper_verification=$inspected_verification
helper_sha256=$inspected_sha256

if [ "$binary_inspected" != 'true' ] || [ "$helper_inspected" != 'true' ]; then
    status='ARTIFACT_INVENTORY_UNVERIFIED'
    reason='An explicitly selected code artifact could not be inventoried. No install, signing, fallback or execution was attempted.'
    emit
    exit 2
fi
status='INVENTORY_COMPLETE'
reason='Requested read-only inventory completed. No sandbox, policy, helper protocol, descendant stop, resource enforcement or release trust was tested. A zero exit is not isolation acceptance.'
emit
exit 0
