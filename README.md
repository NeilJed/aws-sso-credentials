# aws-sso-credentials
## About
*aws-sso-credentials* - A simple Python tool to simplify getting short-term credential tokens for CLI/Boto3 operations when using AWS SSO. Uses standard AWS CLI configuration files and allows easy swapping between roles/accounts

## Motivation
In my organisation we use various CLI/Boto3 based tools with AWS. We have several accounts/roles and need a way to handle MFA, switch between accounts/roles, grab temporary session credentials and make sure they're up to date. To this end our go-to tool of choice was [Limes](https://github.com/otm/limes).

We switched to using [AWS SSO](https://aws.amazon.com/single-sign-on/) linked to our Azure AD to centralise user management. This works great for Single-Sign-On but and the new AWS CLI v2 supports AWS SSO natively. However, getting temporary credentials for use with Boto3 based apps, especially one that doesn't support profiles was a huge problem.

This script is a quick work around to give us something functional that fits with our way of working until something better comes along.

## How it works
This script piggy-backs on the new AWS CLI tool to read the SSO credentials cache and then makes Boto3 calls to retrieve the temporary credentials for the relevant account/role you want.

It uses the standard AWS CLI configuration tools, can trigger a SSO Login session if needed and gives you an interactive command line interface to switch between the role and account you want. It will can also copy your chosen profile/credentials into the default profile for times where don't want/can't tell your application to use a specific profile.

## Prerequisites
The script is written in Python 3 and requires a working installation of [version 2 of the AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html).

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

2. Run the CLI tool at least once using one of the profiles you created so that the SSO cache is created.

```bash
  aws sso login --profile dev-env
```

3. Copy the `awsso` script to somewhere you can run it. Usually somewhere on your `%PATH%` or make a symlink to it from somewhere like `/usr/local/bin`. Make sure to make it executeable, i.e. `chmod 775 awssso`.

That's it! You should be good to go! Try running `awssso -h` to see the list of commands.

## Using the script


