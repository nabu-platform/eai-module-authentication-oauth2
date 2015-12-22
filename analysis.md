# Google

The documentation for web servers is available [here](https://developers.google.com/identity/protocols/OAuth2WebServer#example)

## The redirect TO google

- To authenticate the client, redirect to this endpoint: `https://accounts.google.com/o/oauth2/auth`. Use these query parameters:
	- **response_type**: Fixed value `code`
	- **client_id**: The client id obtained from the developer console
	- **redirect_uri**: The user will be redirected here after login, this url must exactly match a registered URL in the developer console
	- **scope**: the scope determines which information you are requesting, set to `email profile`
	- **state**: you can use this to generate custom state (e.g. csrf token) when redirecting the user. It is echoed back by google allowing you to verify it
	- **access_type**: in some cases you need `offline` access (backup service, blog poster,...) but the default is `online`
	- **approval_prompt**: set to `auto`to have the user only consent once. Set to `force` to have the user consent every time (not sure why?)
	- **login_hint**: if you already know which user is trying to log in, use this to send the email address or some other identifier (not useful here)
	- **include_granted_scopes**: set to `true` to incrementally grant new scopes (you also get the previously agreed upon ones). This allows you to only request access to something at the time you need it **while keeping the same access token**. Otherwise you would have an access token per requested scope.
	
When googling for scopes, you often get redirected to use these scopes:

- https://www.googleapis.com/auth/userinfo.email
- https://www.googleapis.com/auth/userinfo.profile

If you go to these endpoints, they simply return `userinfo.email` and `userinfo.profile`. It is currently unclear whether these values have to be put into scope or as state above `email profile` which was copied from the google site itself.

## The redirect FROM google

After google has succeeded or failed in authenticating the user and/or granting your application permissions, it will redirect to the URL you configured in the above.

It adds one of two query parameters:

- **error**: for example `access_denied`
- **code**: an authorization code which can be used to get the access token

Some (linkedin) also return:

- **error_description**: a further description of the error

## Getting the access token

With the authorization code we received, we can get the access token from this url: `https://www.googleapis.com/oauth2/v3/token` with the following parameters:

- **code**: the code we received
- **client_id**: the client id from the developers console
- **client_secret**: our secret code
- **redirect_uri**: one of the redirect uris listed in the developer console (not sure if this has to be the same as above or any)
- **grant_type**: Fixed value for oauth2: `authorization_code`

These parameters have to be encoded as a form POST submit (application/x-www-form-urlencoded)

A successful response looks like this (it can contain more information, but this is the minimum):

```json
{
	"access_token":"1/fFAGRNJru1FTz70BzhT3Zg",
	"expires_in":3920,
	"token_type":"Bearer"
}
```

The expiry time is in seconds.

## Accessing the google API

To access the google API with the token, you can add it as a query parameter: `access_token=<token>`

However, the better option (preferred by google) is to send it as a header: `Authorization: Bearer <token>`

## Getting the actual user data

The [api for user information](https://www.googleapis.com/oauth2/v1/userinfo?alt=json) should then return something like this:

```json
{ "id": "xx", "name": "xx", "given_name": "xx", "family_name": "xx", "link": "xx", "picture": "xx", "gender": "xx", "locale": "xx" }
```

This "seems" like the data for the profile. According to one post there should also be an "email" field in there, presumably for the scope email.

# Facebook

## Redirect TO facebook

Use the URL: `https://graph.facebook.com/oauth/authorize` with more or less the same core query parameters as above.

The scopes are slightly different, a full list of scopes (permissions) can be found [here](https://developers.facebook.com/docs/facebook-login/permissions/v2.5).
In our case we are interested in `email` and `public_profile`.

## Redirect FROM facebook

Same as above.

## Getting the access token

The method is the same, the url is: `https://graph.facebook.com/oauth/access_token`

## Getting the actual user data

The url `https://graph.facebook.com/me` can be approached to request user data, in this case the `access_token` must be sent as a request parameter

# Linked In

## Redirect TO linkedin

The documentation can be found [here](https://developer.linkedin.com/docs/oauth2)

The URL to call: `https://www.linkedin.com/uas/oauth2/authorization`

The scopes we are interested in: `r_fullprofile` and `r_emailaddress`

## Getting the access token

The url: `https://www.linkedin.com/uas/oauth2/accessToken`

This should also be a POST request that is form encoded.

Note that the bearer header also seems supported.

More information: https://developer-programs.linkedin.com/documents/profile-api
