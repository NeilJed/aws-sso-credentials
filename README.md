# aws-sso-credentials
## About
*aws-sso-credentials* - A simple Python tool to simplify getting short-term credential tokens for CLI/Boto3 operations when using AWS SSO. Uses standard AWS CLI configuration files and allows easy swapping between roles/accounts.

## Motivation
In my organisation we use various CLI/Boto3 based tools with AWS. We have several accounts/roles and need a way to handle MFA, switch between accounts/roles, grab temporary session credentials and make sure they're up to date. To this end our go-to tool of choice was [Limes](https://github.com/otm/limes).

We switched to using [AWS SSO](https://aws.amazon.com/single-sign-on/) linked to our Azure AD to centralise user management. This works great for Single-Sign-On but and the new AWS CLI v2 supports AWS SSO natively. However, getting temporary credentials for use with Boto3 based apps, especially one that doesn't support profiles was a pain involving copying credentials from a web portal, exporting environment variables and a lot of error prone manual steps.

This script is a quick work around to give us something functional that fits with our way of working until something better comes along. Maybe it works for you too.

## How it works
This script piggy-backs on the new AWS CLI tool to read the SSO credentials cache and then makes Boto3 calls to retrieve the temporary credentials for the relevant account/role you want.

It uses the standard AWS CLI configuration files, can trigger a SSO login session if needed and gives you an interactive command line interface to switch between the role and account you want. It will can also copy your chosen profile/credentials into the default profile for times where don't want/can't tell your application to use a specific profile.

## Prerequisites
The script is written in Python 3 and requires a working installation of [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html).

The scripts dependencies are defined in the `requirements.txt` file. You can install these with:

```bash
  pip install -r requirements.txt
```

## Setting up
1. Install the AWS CLI v2 and [configure your profiles](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html) as per the documentation. For example:

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

2. Run the AWS CLI tool *at least once* using one of the profiles you created so that the SSO cache is created.

```bash
  aws sso login --profile dev-env
```

4. Copy the `awssso` script to somewhere you can run it. Usually somewhere on your `%PATH%` or make a symlink to it from somewhere like `/usr/local/bin`. Make sure to make it executeable, i.e. `chmod ug+w awssso`.

5. In the `awssso` script, edit the `AWS_CLI2` variable to point to where the AWS CLI program is installed on your system.

That's it. You should be good to go.

## Useage

You can run `awssso` passing it the name of the profile you want credentials for.

```bash
  $ awssso dev-env
```

If you don't pass a profile name it will allow you to select from a list:

```
   $ awssso
   
   [?] Please select an AWS config profile: dev-env
   default
 > dev-env
   prod-env
```

Once the profile is selected, the script will check if you're current SSO credentials are valid and warn you if they will expire soon. It will then use these credentials to get the short term-credentials and copy them to your `.aws/credentials` file.

You can then use these credentials with the tool of your choice either by passing the profile name, or setting the profile in your environment:

```bash
  export AWS_PROFILE=dev-env
```

If you want to avoid having to set a profile, use the `-d` option detailed below.

### Options

- `-h, --help` - Show help and a list of command line options.
- `-v, --verbose` Verbose mode. Tells you what the script is doing and dumps information about when your SSO credentials and temporary credentials expire.
- `--login` Invokes the AWS CLI to perform a SSO login and refresh SSO credentials.
- `-d, --use-default` Copies the chosen profile and credentials to the default profile. This removes the need to pass a profile name or export the `AWS_PROFILE` environment variable.

## Example

Here is a simple example that I use in my own day-to-day routine.

```
  $ awsso --login -v -d dev-env
  
  Attempting to automatically open the SSO authorization page in your default browser.
  If the browser does not open or you wish to use a different device to authorize this request,
  open the following URL:

  https://device.sso.eu-west-1.amazonaws.com/

  Then enter the code:

  ABCD-WXYZ
  Successully logged into Start URL: https://yoursso.awsapps.com/start

  Reading profile: [profile dev-env]

  Checking for SSO credentials...
  Found credentials. Valid until 2020-05-01 22:32:11 UTC

  Fetching short-term CLI/Boto3 session token...
  Got session token. Valid until 2020-05-01 18:32:11 UTC

  Adding to credential files under [default]
  Copying profile [profile dev-env] to [default]
```
