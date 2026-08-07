# aws-sso-credentials
## About
*aws-sso-credentials* - A simple Python tool to simplify getting short-term credential tokens for CLI/Boto3 operations when using AWS SSO. Uses standard AWS CLI configuration files and allows easy swapping between roles/accounts.

## Motivation
In my organisation we use various CLI/Boto3 based tools with AWS. We have several accounts/roles and need a way to handle MFA, switch between accounts/roles, grab temporary session credentials and make sure they're up to date. To this end our go-to tool of choice was [Limes](https://github.com/otm/limes).

We switched to using [AWS SSO](https://aws.amazon.com/single-sign-on/) linked to our Azure AD to centralise user management. This works great for Single-Sign-On and the new AWS CLI v2 supports AWS SSO natively. However, getting temporary credentials for use with Boto3 based apps, especially one that doesn't support profiles was a pain involving copying credentials from a web portal, exporting environment variables and a lot of error prone manual steps.

This script is a quick work around to give us something functional that fits with our way of working until something better comes along. Maybe it works for you too.

## How it works
This tool performs the SSO device-code login itself via Boto3, caches the resulting SSO credentials (in the same location the AWS CLI uses), then makes Boto3 calls to retrieve the temporary credentials for the relevant account/role you want.

It uses the standard AWS CLI configuration files, can trigger a SSO login session if needed and gives you an interactive command line interface to switch between the role and account you want. It can also copy your chosen profile/credentials into the default profile for times where you don't want/can't tell your application to use a specific profile.

## Prerequisites
The tool requires a working installation of [uv](https://docs.astral.sh/uv/getting-started/installation/) or [pipx](https://pipx.pypa.io/stable/installation/). No AWS CLI installation is needed — the SSO login and credential retrieval are done internally via Boto3.

## Setting up
1. Configure your profiles in `~/.aws/config` as per the [AWS SSO documentation](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html). For example:

```ini
[profile dev-env]
region = eu-west-1
sso_start_url = https://yoursso.awsapps.com/start
sso_region = eu-west-1
sso_account_id = 123456654321
sso_role_name = DevOps

[profile prod-env]
region = eu-west-1
sso_start_url = https://yoursso.awsapps.com/start
sso_region = eu-west-1
sso_account_id = 543210012345
sso_role_name = DevOps
```

The newer `sso_session`-based profile format is also supported, as is chaining
profiles together with `source_profile` to inherit shared options:

```ini
[sso-session my-sso]
sso_start_url = https://yoursso.awsapps.com/start
sso_region = eu-west-1

[profile dev-env]
region = eu-west-1
sso_session = my-sso
sso_account_id = 123456654321
sso_role_name = DevOps
```

2. Install the tool as a standalone CLI with `uv`:

```bash
  uv tool install git+https://github.com/NeilJed/aws-sso-credentials
```

Or from a local clone:

```bash
  uv tool install .
```

That's it. `awssso` is now on your `PATH`. You should be good to go.

If you'd rather not use `uv`, [pipx](https://pipx.pypa.io/stable/installation/) works the same way:

```bash
  pipx install git+https://github.com/NeilJed/aws-sso-credentials
```

Or from a local clone:

```bash
  pipx install .
```

## Usage

You can run `awssso` passing it the name of one or more profiles you want credentials for, space separated:

```bash
  $ awssso dev-env
  $ awssso dev-env prod-env
```

If you don't pass any profile names it will allow you to pick one or more from a checkbox list (type to filter, space to toggle, enter to confirm):

```
   $ awssso

   [?] Please select AWS profiles to authenticate
    ○ default
  > ● dev-env
    ○ prod-env
```

For each profile selected, the tool checks whether your current SSO credentials are valid (warning if they'll expire soon, or logging in again if needed), then fetches short-term credentials and writes them to your `.aws/credentials` file. If multiple profiles share the same SSO session, you'll only be prompted to log in once. If fetching credentials for one profile fails, the tool reports the error and carries on with the rest rather than stopping.

You can then use these credentials with the tool of your choice either by passing the profile name, or setting the profile in your environment:

```bash
  export AWS_PROFILE=dev-env
```

If you want to avoid having to set a profile, use the `-d` option detailed below (only valid when selecting a single profile).

### Options

- `-h, --help` - Show help and a list of command line options.
- `-v, --verbose` Verbose mode. Tells you what the script is doing, dumps information about when your SSO credentials and temporary credentials expire, and shows the role/region alongside each profile in the picker.
- `--login` Forces a fresh SSO login and refreshes SSO credentials, even if a valid cached login exists.
- `-d, --use-default` Copies the chosen profile and credentials to the default profile. This removes the need to pass a profile name or export the `AWS_PROFILE` environment variable. Ignored (with a warning) if more than one profile is given.

## Example

Here is a simple example that I use in my own day-to-day routine.

```
  $ awssso --login -v -d dev-env

  Reading profile: [dev-env]

  Checking for SSO credentials...

  Attempting to automatically open the SSO authorization page in your default browser.
  If the browser does not open or you wish to use a different device to authorize this request,
  open the following URL:

  https://device.sso.eu-west-1.amazonaws.com/

  Then enter the code:

  ABCD-WXYZ
  Successfully logged into Start URL: https://yoursso.awsapps.com/start

  Fetching short-term CLI/Boto3 session token...
  Got session token. Valid until 2020-05-01 18:32:11 (Local)

  Adding to credential files under [dev-env]
  Adding to credential files under [default]
  Copying profile [dev-env] to [default]
```
